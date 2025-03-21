use ldap3::Scope;
use crate::ldap::ldap::{LDAP, ConnSecurity};

mod ldap;


fn main() {
    let mut ldap_connection = LDAP::new("ldap-fusion.i.personaltardis.me".parse().unwrap(),
                                        None, ConnSecurity::None,
                                        "dc=personaltardis,dc=me".parse().unwrap(), None);
    ldap_connection.list_units(Some(Scope::Subtree));
    ldap_connection.close_connection();
}
