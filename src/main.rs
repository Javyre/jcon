extern crate jack;
extern crate regex;

use regex::Regex;

use std::result;
use std::sync::mpsc::{
    channel,
    Sender,
    Receiver,
};

use std::env;

fn main() {
    println!("Hello, world!");

    if env::var_os("JCON_NO_SOURCE").is_none() {
        source_cfg();
    }

    let cfg = Config::parse_env().unwrap();
    let cli = Patchbay::open_client("jcon").expect("creating patchbay");

    let chan = channel();
    cli.run(cfg, chan).expect("running patchbay");
}

fn source_cfg() {
    use std::process;
    use std::os::unix::process::CommandExt;

    let exec_err = process::Command::new("sh")
        .args(&[
              "-c",
              &format!(
                  "
export JCON_CONN_COUNT=0
export JCON_DCONN_COUNT=0

for file in {ctm} {xdg} {hom} {etc}; do
    [ -n {fil} ] && 
    [ -r {fil} ] && . {fil} && break
done

export JCON_NO_SOURCE=1
exec \"$@\"\
                  ",
                  fil = "\"$file\"",

                  ctm = "\"$JCON_CUSTOM_RC\"",
                  xdg = "\"$XDG_CONFIG_HOME/jcon/rc\"",
                  hom = "\"$HOME/.config/jcon/rc\"",
                  etc = "\"/etc/jcon/rc\"",
              ),
        ])
        .arg("jcon-launch") // $0
        .arg(env::current_exe().unwrap()) // $1
        .args(&env::args().skip(1).collect::<Vec<String>>()) // $2-$n
        .exec();

    panic!("Failed to exec jcon launcher: {}", exec_err);
}

#[derive(Debug)]
struct Patchbay {
    cli: jack::Client,
}

#[derive(Debug, Clone)]
struct In<T>(T);
#[derive(Debug, Clone)]
struct Out<T>(T);

type PFlags = jack::PortFlags;

#[derive(Debug, Eq, PartialEq)]
struct PortName(String);

#[derive(Debug, Eq, PartialEq)]
struct PName(String);

type IName = In<PName>;
type OName = Out<PName>;

#[derive(Debug, Clone)]
struct PortRegex(Regex);

#[derive(Debug, Clone)]
struct PRegex(Regex);

type IRegex = In<PRegex>;
type ORegex = Out<PRegex>;

#[derive(Debug)]
struct ConnMap {
    map: Vec<(ORegex, IRegex)>,
}

#[derive(Debug)]
struct Config {
    pub conns:    ConnMap,
    pub disconns: ConnMap,
}

#[derive(Debug)]
enum UserCommand {
    Connect(ORegex, IRegex),
    Disconnect(ORegex, IRegex),
    Toggle(ORegex, IRegex),
}

type UserCommandResponse = Result<()>;

#[derive(Debug)]
enum Command {
    EnsureConnected(PortRegex, PortRegex),
    EnsureDisConnected(PortRegex, PortRegex),
}

#[derive(Debug)]
enum Notification {
    PortRegistered(PName), // -> Check if port is in rules & Connect?
    PortUnregistered(PName), // -> Nothing
    PortsConnected(OName, IName), // -> Check if port is in rules & Disconnect?
    PortsDisconnected(OName, IName), // -> Check if port is in rules & Reconnect?
}

#[derive(Debug)]
enum Signal {
    UserCommand(UserCommand, Sender<UserCommandResponse>),
    Command(Command),
    Notification(Notification),
}

#[derive(Clone)]
enum Control { Continue, Finish }

struct Notifier {
    sigs: Sender<Signal>,
}

#[derive(Debug)]
struct RunningPatchbay {
    cli: jack::AsyncClient<Notifier, ()>,
    cfg: Config,
}

#[derive(Clone, Debug)]
enum Error {
    InvalidJson,
    ParseIntError(std::num::ParseIntError),
    InvalidEnv(env::VarError),
    InvalidRegex(regex::Error),

    CannotOpenClient(jack::Error),
    CannotActivateClient(jack::Error),
    CannotConnectPorts(jack::Error),
    CannotDisconnectPorts(jack::Error),
    CannotCheckPorts(jack::Error),
}

type Result<T> = result::Result<T, Error>;

impl From<regex::Error> for Error {
    fn from(e: regex::Error) -> Error {
        Error::InvalidRegex(e)
    }
}

impl From<env::VarError> for Error {
    fn from(e: env::VarError) -> Error {
        Error::InvalidEnv(e)
    }
}

impl IName  { pub fn inner(&self) -> &String { &(self.0).0 } }
impl OName  { pub fn inner(&self) -> &String { &(self.0).0 } }
impl IRegex { pub fn inner(&self) -> &Regex  { &(self.0).0 } }
impl ORegex { pub fn inner(&self) -> &Regex  { &(self.0).0 } }

impl ConnMap {
    pub fn from_env(prefix: impl AsRef<str>) -> Result<Self> {
        let count = env::var(format!("{}_COUNT", prefix.as_ref()))?;
        let count = str::parse::<usize>(&count)
            .map_err(|e| Error::ParseIntError(e))?;

        let prefix = prefix.as_ref();

        let mut map = vec![];

        for i in 0..count {
            println!("{}: {} <--> {}",
                     i,
                     env::var(format!("{}_{}_A", prefix, i))?,
                     env::var(format!("{}_{}_B", prefix, i))?,
                     );

            map.push((
                Out(PRegex(Regex::new(&env::var(format!("{}_{}_A", prefix, i))?)?)),
                In(PRegex(Regex::new(&env::var(format!("{}_{}_B", prefix, i))?)?)),
            ));
        }

        Ok(Self{ map })
    }

    // TODO: Dedup these two functions
    pub fn find_with_in(&self, n: &IName) -> Vec<ORegex> {
        self.map.iter()
            .filter(|(_, i)|i.matches(n)).map(|(o, _)|o.clone()).collect()
    }

    pub fn find_with_out(&self, n: &OName) -> Vec<IRegex> {
        self.map.iter()
            .filter(|(o, _)|o.matches(n)).map(|(_, i)|i.clone()).collect()
    }

    pub fn insert(&mut self, o: ORegex, i: IRegex) {
        self.map.push((o, i));
    }
}

impl Config {
    pub fn parse_env() -> Result<Self> {
        let conns    = ConnMap::from_env("JCON_CONN")?;
        let disconns = ConnMap::from_env("JCON_DCONN")?;
        Ok(Self { conns, disconns })
    }

    pub fn connect(&mut self, pa: ORegex, pb: IRegex) {
        self.conns.insert(pa, pb)
    }

    pub fn disconnect(&mut self, pa: ORegex, pb: IRegex) {
        self.disconns.insert(pa, pb)
    }

    fn should_connect(&self, pa: &OName, pb: &IName) -> bool {
        let found = self.conns.find_with_out(pa).iter()
            .any(|other_rgx| other_rgx.matches(pb));

        let blacklisted = self.disconns.find_with_out(pa).iter()
            .any(|other_rgx| other_rgx.matches(pb));

        found && (!blacklisted)
    }
}

impl Patchbay {
    pub fn open_client(cli_name: impl AsRef<str>) -> Result<Self> {
        let (cli, stat) = jack::Client::new(
                cli_name.as_ref(),
                jack::ClientOptions::empty(),
            )
            .map_err(|e| Error::CannotOpenClient(e))?;

        if !stat.is_empty() {
            eprintln!("Client status on open: {:?}", stat);
        }

        Ok(Self { cli })
    }

    pub fn run(self, cfg: Config, chan: (Sender<Signal>, Receiver<Signal>))
        -> Result<()> {
        RunningPatchbay::run_kit(self, cfg, chan)
    }
}

impl PRegex {
    pub fn resolve(&self, cli: &jack::Client, flags: PFlags) 
        -> impl Iterator<Item=PName> {
        // To avoid lifetime issues with returning the iterator
        let rgx = self.0.clone();
        cli
            .ports(None, None, flags)
            .into_iter()
            .filter(move |pn| rgx.is_match(pn))
            .map(|s|PName(s))
    }

    pub fn matches(&self, PName(pn): &PName) -> bool { self.0.is_match(pn) }
}

impl IRegex {
    pub fn resolve(&self, cli: &jack::Client) -> impl Iterator<Item=IName> {
        self.0.resolve(cli, PFlags::IS_INPUT).map(|pr|In(pr))
    }

    pub fn matches(&self, n: &IName) -> bool { self.0.matches(&n.0) }
}

impl ORegex {
    pub fn resolve(&self, cli: &jack::Client) -> impl Iterator<Item=OName> {
        self.0.resolve(cli, PFlags::IS_OUTPUT).map(|pr|Out(pr))
    }

    pub fn matches(&self, n: &OName) -> bool { self.0.matches(&n.0) }
}

impl Notifier {
    pub fn new(sigs: Sender<Signal>) -> Self { Self { sigs } }

    fn port_name(c: &jack::Client, id: jack::PortId) -> PName {
        // Impossible errors
        PName(c
              .port_by_id(id)
              .expect("Port by id not found in notifier (Impossible)")
              .name()
              .expect("Getting name from port in notifier (Impossible)")
              .to_owned())
    }

    fn send_notification(&self, n: Notification) {
        // Impossible errors
        self.sigs
            .send(Signal::Notification(n))
            .expect("Notifying patchbay (Impossible)");
    }
}

unsafe impl std::marker::Send for Notifier {}

impl jack::NotificationHandler for Notifier {
    fn port_registration(&mut self, c: &jack::Client, id: jack::PortId,
                         is_registered: bool) {

        let name = Self::port_name(c, id);

        self.send_notification(match is_registered {
            true  => Notification::PortRegistered(name),
            false => Notification::PortUnregistered(name),
        });
    }

    fn ports_connected(&mut self, c: &jack::Client, ida: jack::PortId,
                       idb: jack::PortId, are_connected: bool) {

        let name_a = Out(Self::port_name(c, ida));
        let name_b = In(Self::port_name(c, idb));

        self.send_notification(match are_connected {
            true  => Notification::PortsConnected(name_a, name_b),
            false => Notification::PortsDisconnected(name_a, name_b),
        });
    }
}

impl RunningPatchbay {
    pub fn run_kit(pb: Patchbay, cfg: Config,
                   chan: (Sender<Signal>, Receiver<Signal>))
        -> Result<()> {
        let (sender, sigs) = chan;

        let cli = pb.cli.activate_async(Notifier::new(sender.clone()), ())
            .map_err(|e| Error::CannotActivateClient(e))?;

        let mut this = Self { cli, cfg };

        this.init_corrections()?;

        for s in sigs {
            match this.handle(s) {
                Ok(Control::Finish) => return Ok(()),
                Err(e)              => return Err(e),

                _ => (),
            }
        }
        unreachable!()
    }

    fn init_corrections(&self) -> Result<()> {
        self.all_out_ports().map(|an|{
                self.all_in_ports().map(|bn|{
                    let are_connected  = self.are_connected(&an, &bn)?;
                    let should_connect = self.should_connect(&an, &bn);
                    match (are_connected, should_connect) {
                        (true, false) => self.disconnect(&an, &bn),
                        (false, true) => self.connect(&an, &bn),
                        _ => Ok(())
                    }
                })
                .collect::<Result<()>>()
            })
        .collect::<Result<()>>()
    }

    fn handle(&mut self, sig: Signal) -> Result<Control> {
        match sig {
            Signal::UserCommand(c, r) => {
                let res = self.handle_user_command(c);
                r.send(res.clone().map(|_|()))
                    .expect("sending response to client handler thread");
                Ok(res.unwrap_or(Control::Continue))
            },

            Signal::Command(..)       => unimplemented!(),
            Signal::Notification(n)   => self.handle_notification(n),
        }
    }

    fn handle_user_command(&mut self, c: UserCommand) -> Result<Control> {
        match c {
            UserCommand::Connect(pa, pb) => {
                self.connect_rgx(&pa, &pb)?;
                self.cfg.connect(pa, pb);
            },

            UserCommand::Disconnect(pa, pb) => {
                self.disconnect_rgx(&pa, &pb)?;
                self.cfg.disconnect(pa, pb);
            },

            UserCommand::Toggle(pa, pb) => unimplemented!(),
        }
        Ok(Control::Continue)
    }

    fn handle_notification(&mut self, n: Notification) -> Result<Control> {
        match n {
            Notification::PortRegistered(an) => {
                if self.is_input(&an) {
                    let i = In(an);
                    self.all_out_ports()
                        .filter(|o| self.should_connect(&o, &i))
                        .map(|o| self.connect(&o, &i))
                        .collect::<Result<()>>()?;
                } else {
                    let o = Out(an);
                    self.all_in_ports()
                        .filter(|i| self.should_connect(&o, &i))
                        .map(|i| self.connect(&o, &i))
                        .collect::<Result<()>>()?;
                }
            },
            Notification::PortUnregistered(_) => (), // Do nothing

            Notification::PortsConnected(pa, pb) => {
                if !self.should_connect(&pa, &pb) {
                    self.disconnect(&pa, &pb)?;
                }
            },
            Notification::PortsDisconnected(pa, pb) => {
                if self.should_connect(&pa, &pb) {
                    self.connect(&pa, &pb)?;
                }
            }
        }
        Ok(Control::Continue)
    }

    fn is_input(&self, p: &PName) -> bool {
        self.cli.as_client().port_by_name(&p.0)
            .expect("requesting port by name") // This should be impossible
            .flags() 
            .contains(PFlags::IS_INPUT)
    }

    fn all_x_ports(&self, flags: PFlags) -> impl Iterator<Item=PName> {
        self.cli.as_client()
            .ports(None, None, flags)
            .into_iter()
            .map(|bn| PName(bn))
    }
    fn all_in_ports(&self) -> impl Iterator<Item=IName> {
        self.all_x_ports(PFlags::IS_INPUT).map(|bn| In(bn))
    }

    fn all_out_ports(&self) -> impl Iterator<Item=OName> {
        self.all_x_ports(PFlags::IS_OUTPUT).map(|bn| Out(bn))
    }

    fn connect(&self, pa: &OName, pb: &IName) -> Result<()> {
        self.cli.as_client().connect_ports_by_name(&pa.inner(), &pb.inner())
            .map_err(|e| Error::CannotConnectPorts(e))
    }

    fn disconnect(&self, pa: &OName, pb: &IName) -> Result<()> {
        self.cli.as_client().disconnect_ports_by_name(&pa.inner(), &pb.inner())
            .map_err(|e| Error::CannotDisconnectPorts(e))
    }

    fn connect_rgx(&self, pa: &ORegex, pb: &IRegex) -> Result<()> {
        let cli = self.cli.as_client();
        for pa in pa.resolve(cli) {
            for pb in pb.resolve(cli) {
                self.connect(&pa, &pb)?;
            }
        }
        Ok(())
    }

    fn disconnect_rgx(&self, pa: &ORegex, pb: &IRegex) -> Result<()> {
        let cli = self.cli.as_client();
        for pa in pa.resolve(cli) {
            for pb in pb.resolve(cli) {
                self.disconnect(&pa, &pb)?;
            }
        }
        Ok(())
    }

    fn are_connected(&self, pa: &OName, pb: &IName) -> Result<bool> {
        let cli = self.cli.as_client();

        cli.port_by_name(&pa.inner())
            .map(|p| p.is_connected_to(&pb.inner()).map_err(|e| Error::CannotCheckPorts(e)))
            .unwrap_or(Ok(false))
    }

    fn should_connect(&self, pa: &OName, pb: &IName) -> bool {
        self.cfg.should_connect(pa, pb)
    }
}
