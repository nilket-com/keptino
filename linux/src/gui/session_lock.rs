//! Locks the vault when the desktop session locks or the machine is about to
//! sleep, as KeePassXC does. logind announces sleep on the system bus; the
//! desktop announces a locked screen through logind's LockedHint property,
//! the session's Lock signal, or a screensaver interface on the session bus.
//! Any one of them is enough. A forged signal can only lock the vault, never
//! open it, so senders are filtered but not trusted.

use crate::{gui::messages::Message, logger::warn};
use iced::{
	Subscription,
	futures::{SinkExt, Stream, StreamExt, stream},
};
use std::collections::HashMap;
use zbus::{
	Connection, MatchRule, Message as Signal, MessageStream, Variant, message::Type,
};

const LOGIND: &str = "org.freedesktop.login1";

pub fn subscription() -> Subscription<Message> {
	Subscription::run(listen)
}

fn listen() -> impl Stream<Item = Message> {
	iced::stream::channel(4, async move |mut output| {
		// The connections must outlive their streams, so they live here.
		let system = Connection::system().await.ok();
		let session = Connection::session().await.ok();
		let mut signals = Vec::new();
		for (connection, rules) in [
			(&system, system_rules()),
			(&session, session_rules()),
		] {
			let Some(connection) = connection else {
				continue;
			};
			for rule in rules.into_iter().flatten() {
				if let Ok(messages) = MessageStream::for_match_rule(rule, connection, None).await
				{
					signals.push(messages.boxed());
				}
			}
		}
		if signals.is_empty() {
			warn("No D-Bus connection: the vault will not lock on sleep or session lock.");
			return;
		}
		let mut merged = stream::select_all(signals);
		while let Some(message) = merged.next().await {
			if message.is_ok_and(|message| locks(&message))
				&& output.send(Message::Lock).await.is_err()
			{
				return;
			}
		}
	})
}

fn system_rules() -> Vec<zbus::Result<MatchRule<'static>>> {
	let logind = || MatchRule::builder().msg_type(Type::Signal).sender(LOGIND);
	vec![
		logind()
			.interface("org.freedesktop.login1.Manager")
			.member("PrepareForSleep")
			.build(),
		logind()
			.interface("org.freedesktop.login1.Session")
			.member("Lock")
			.build(),
		logind()
			.interface("org.freedesktop.DBus.Properties")
			.member("PropertiesChanged")
			.path_namespace("/org/freedesktop/login1/session")
			.arg(0, "org.freedesktop.login1.Session")
			.build(),
	]
}

fn session_rules() -> Vec<zbus::Result<MatchRule<'static>>> {
	["org.freedesktop.ScreenSaver", "org.gnome.ScreenSaver"]
		.into_iter()
		.map(|interface| {
			MatchRule::builder()
				.msg_type(Type::Signal)
				.interface(interface)
				.member("ActiveChanged")
				.build()
		})
		.collect()
}

/// Whether a signal means the session is locking or the machine is sleeping.
/// The opposite transitions (waking, unlocking) are ignored.
fn locks(message: &Signal) -> bool {
	let header = message.header();
	let (Some(interface), Some(member)) = (header.interface(), header.member()) else {
		return false;
	};
	match (&**interface, &**member) {
		("org.freedesktop.login1.Manager", "PrepareForSleep")
		| ("org.freedesktop.ScreenSaver" | "org.gnome.ScreenSaver", "ActiveChanged") => {
			message.body().deserialize::<bool>().unwrap_or(false)
		}
		("org.freedesktop.login1.Session", "Lock") => true,
		("org.freedesktop.DBus.Properties", "PropertiesChanged") => message
			.body()
			.deserialize::<(String, HashMap<String, Variant>, Vec<String>)>()
			.is_ok_and(|(interface, changed, _)| {
				interface == "org.freedesktop.login1.Session"
					&& matches!(changed.get("LockedHint"), Some(Variant::Bool(true)))
			}),
		_ => false,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn signal<B: serde::Serialize + zbus::zvariant::DynamicType>(
		interface: &str,
		member: &str,
		body: &B,
	) -> Signal {
		Signal::signal("/org/freedesktop/login1", interface, member)
			.build(body)
			.unwrap()
	}

	#[test]
	fn only_locking_and_sleeping_transitions_lock() {
		assert!(locks(&signal("org.freedesktop.login1.Manager", "PrepareForSleep", &true)));
		assert!(!locks(&signal("org.freedesktop.login1.Manager", "PrepareForSleep", &false)));
		assert!(locks(&signal("org.freedesktop.ScreenSaver", "ActiveChanged", &true)));
		assert!(locks(&signal("org.gnome.ScreenSaver", "ActiveChanged", &true)));
		assert!(!locks(&signal("org.gnome.ScreenSaver", "ActiveChanged", &false)));
		assert!(locks(&signal("org.freedesktop.login1.Session", "Lock", &())));
		assert!(!locks(&signal("org.freedesktop.login1.Session", "Unlock", &())));
		let locked: (&str, HashMap<&str, Variant>, Vec<&str>) = (
			"org.freedesktop.login1.Session",
			HashMap::from([("LockedHint", Variant::Bool(true))]),
			vec![],
		);
		assert!(locks(&signal("org.freedesktop.DBus.Properties", "PropertiesChanged", &locked)));
		let unlocked: (&str, HashMap<&str, Variant>, Vec<&str>) =
			(locked.0, HashMap::from([("LockedHint", Variant::Bool(false))]), vec![]);
		assert!(!locks(&signal("org.freedesktop.DBus.Properties", "PropertiesChanged", &unlocked)));
		let other: (&str, HashMap<&str, Variant>, Vec<&str>) =
			("org.freedesktop.login1.Session", HashMap::from([("Active", Variant::Bool(true))]), vec![]);
		assert!(!locks(&signal("org.freedesktop.DBus.Properties", "PropertiesChanged", &other)));
		assert!(system_rules().into_iter().chain(session_rules()).all(|rule| rule.is_ok()));
	}
}
