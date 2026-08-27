use crate::edge::EdgeKind;
use crate::node::NodeKind;
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeClass {
    Host,
    AdStructure,
    Principal,
    Group,
    Network,
    Service,
    Share,
    Cloud,
    Finding,
    Artifact,
    Custom,
}

impl NodeKind {
    pub fn class(self) -> NodeClass {
        use NodeKind::*;
        match self {
            HostWindows | HostLinux | HostMacos | NetworkDevice | Hypervisor | VirtualMachine
            | Container | ContainerHost | DomainController => NodeClass::Host,

            Domain | Forest | OrganizationalUnit | Gpo | CertificateAuthority | CertTemplate => {
                NodeClass::AdStructure
            }

            UserAccount | ComputerAccount | ServiceAccount => NodeClass::Principal,

            Group => NodeClass::Group,

            NetworkSegment | Subnet | Vlan => NodeClass::Network,

            Service | WebApplication => NodeClass::Service,

            Share => NodeClass::Share,

            CloudResource | CloudIdentity => NodeClass::Cloud,

            Finding => NodeClass::Finding,

            Loot => NodeClass::Artifact,

            Custom => NodeClass::Custom,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EdgeRule {
    pub src_classes: &'static [NodeClass],
    pub dst_classes: &'static [NodeClass],
    pub src_kinds: &'static [NodeKind],
    pub dst_kinds: &'static [NodeKind],
}

const NO_C: &[NodeClass] = &[];
const NO_K: &[NodeKind] = &[];

pub const ALL_NODE_KINDS: [NodeKind; 30] = {
    use NodeKind::*;
    [
        HostWindows,
        HostLinux,
        HostMacos,
        NetworkDevice,
        Hypervisor,
        VirtualMachine,
        Container,
        ContainerHost,
        Domain,
        Forest,
        OrganizationalUnit,
        Gpo,
        DomainController,
        CertificateAuthority,
        CertTemplate,
        NetworkSegment,
        Subnet,
        Vlan,
        Service,
        Share,
        WebApplication,
        UserAccount,
        ComputerAccount,
        ServiceAccount,
        Group,
        CloudResource,
        CloudIdentity,
        Finding,
        Loot,
        Custom,
    ]
};

pub const ALL_EDGE_KINDS: [EdgeKind; 64] = {
    use EdgeKind::*;
    [
        MemberOf,
        AdminTo,
        HasLocalAdmin,
        Owns,
        WriteDacl,
        GenericAll,
        ForceChangePassword,
        AddMember,
        PrivEsc,
        ShadowCredentials,
        WriteSpn,
        AllowedToAct,
        AllowedToDelegate,
        ReadGmsaPassword,
        ReadLapsPassword,
        GenericWrite,
        WriteOwner,
        AllExtendedRights,
        WriteGpLink,
        AddSelf,
        UnconstrainedDelegation,
        CanKerberoast,
        CanAsrepRoast,
        Enroll,
        EnrollOnBehalfOf,
        PublishedTo,
        AuthenticatesAs,
        MemberOfDomain,
        ContainsOu,
        LinkedGpo,
        GpoAppliesTo,
        DcFor,
        Trusts,
        DcSync,
        ManageCa,
        HasSession,
        CredentialValidFor,
        DumpedFrom,
        CanRdp,
        CanPsRemote,
        ExecuteDcom,
        CanSsh,
        SqlAdmin,
        SqlLink,
        Coerce,
        RelayTo,
        HostsVm,
        VmHostedOn,
        RunsContainer,
        ListensOn,
        HostedOn,
        ConnectsTo,
        RoutesThrough,
        SameSegment,
        ParentSegment,
        ReachableFrom,
        Affects,
        LootedFrom,
        YieldsCredential,
        EvidenceFor,
        PivotEstablished,
        LateralMovement,
        ExploitableVia,
        Custom,
    ]
};

impl EdgeKind {
    pub fn rule(self) -> EdgeRule {
        use EdgeKind::*;
        use NodeClass as C;
        use NodeKind as K;

        const fn r(
            src_classes: &'static [NodeClass],
            dst_classes: &'static [NodeClass],
        ) -> EdgeRule {
            EdgeRule {
                src_classes,
                dst_classes,
                src_kinds: NO_K,
                dst_kinds: NO_K,
            }
        }
        const fn rk(src_kinds: &'static [NodeKind], dst_kinds: &'static [NodeKind]) -> EdgeRule {
            EdgeRule {
                src_classes: NO_C,
                dst_classes: NO_C,
                src_kinds,
                dst_kinds,
            }
        }

        match self {
            MemberOf => r(&[C::Principal, C::Group], &[C::Group]),

            AdminTo => r(&[C::Principal, C::Group, C::Host], &[C::Host]),
            HasLocalAdmin => r(&[C::Principal, C::Group, C::Host], &[C::Host]),
            Owns => r(
                &[C::Principal, C::Group],
                &[C::Principal, C::Group, C::AdStructure],
            ),
            WriteDacl => r(
                &[C::Principal, C::Group],
                &[C::Principal, C::Group, C::AdStructure],
            ),
            GenericAll => r(
                &[C::Principal, C::Group],
                &[C::Principal, C::Group, C::AdStructure, C::Host],
            ),
            ForceChangePassword => r(&[C::Principal, C::Group], &[C::Principal]),
            AddMember => r(&[C::Principal, C::Group], &[C::Group]),
            PrivEsc => r(
                &[C::Principal, C::Group, C::Host],
                &[C::Principal, C::Group, C::Host, C::AdStructure],
            ),

            ShadowCredentials => r(&[C::Principal, C::Group], &[C::Principal, C::Host]),

            WriteSpn => r(&[C::Principal, C::Group], &[C::Principal]),

            AllowedToAct => r(&[C::Principal, C::Group, C::Host], &[C::Host]),
            AllowedToDelegate => r(&[C::Principal, C::Host], &[C::Host, C::Service]),

            ReadGmsaPassword => r(&[C::Principal, C::Group], &[C::Principal]),
            ReadLapsPassword => r(&[C::Principal, C::Group], &[C::Host]),

            MemberOfDomain => EdgeRule {
                src_classes: &[C::Host, C::Principal, C::Group],
                dst_classes: NO_C,
                src_kinds: NO_K,
                dst_kinds: &[K::Domain],
            },
            ContainsOu => rk(
                &[K::OrganizationalUnit, K::Domain],
                &[K::OrganizationalUnit],
            ),
            LinkedGpo => rk(&[K::Gpo], &[K::OrganizationalUnit, K::Domain]),
            DcFor => rk(&[K::DomainController], &[K::Domain]),
            Trusts => rk(&[K::Domain, K::Forest], &[K::Domain, K::Forest]),

            DcSync => EdgeRule {
                src_classes: &[C::Principal, C::Group],
                dst_classes: NO_C,
                src_kinds: NO_K,
                dst_kinds: &[K::Domain],
            },

            ManageCa => EdgeRule {
                src_classes: &[C::Principal, C::Group],
                dst_classes: NO_C,
                src_kinds: NO_K,
                dst_kinds: &[K::CertificateAuthority],
            },

            HasSession => r(&[C::Principal], &[C::Host]),
            CredentialValidFor => r(
                &[C::Principal, C::Host],
                &[C::Host, C::Service, C::Principal, C::Cloud],
            ),
            DumpedFrom => r(&[C::Host, C::Principal], &[C::Host, C::Principal]),

            CanRdp => r(&[C::Principal, C::Group, C::Host], &[C::Host]),
            CanPsRemote => r(&[C::Principal, C::Group, C::Host], &[C::Host]),
            ExecuteDcom => r(&[C::Principal, C::Group, C::Host], &[C::Host]),
            CanSsh => r(&[C::Principal, C::Group, C::Host], &[C::Host]),

            SqlAdmin => r(&[C::Principal, C::Group, C::Host], &[C::Host, C::Service]),

            Coerce => r(&[C::Host, C::Principal], &[C::Host]),

            HostsVm => rk(&[K::Hypervisor], &[K::VirtualMachine]),
            VmHostedOn => rk(&[K::VirtualMachine], &[K::Hypervisor]),
            RunsContainer => EdgeRule {
                src_classes: &[C::Host],
                dst_classes: NO_C,
                src_kinds: NO_K,
                dst_kinds: &[K::Container],
            },
            ListensOn => r(&[C::Service], &[C::Host]),
            ConnectsTo => r(
                &[C::Host, C::Network, C::Cloud],
                &[C::Host, C::Network, C::Service, C::Cloud],
            ),
            RoutesThrough => r(&[C::Host, C::Network], &[C::Host, C::Network]),
            SameSegment => r(&[C::Host, C::Network], &[C::Host, C::Network]),
            ParentSegment => r(&[C::Host, C::Network], &[C::Network]),
            ReachableFrom => r(
                &[C::Host, C::Network],
                &[C::Host, C::Network, C::Service, C::Cloud],
            ),

            PivotEstablished => r(&[C::Host, C::Network], &[C::Host, C::Network]),
            LateralMovement => r(&[C::Host, C::Principal], &[C::Host]),
            ExploitableVia => r(
                &[
                    C::Host,
                    C::Service,
                    C::Principal,
                    C::Group,
                    C::AdStructure,
                    C::Cloud,
                ],
                &[
                    C::Host,
                    C::Service,
                    C::Principal,
                    C::Group,
                    C::AdStructure,
                    C::Cloud,
                ],
            ),

            GenericWrite => r(
                &[C::Principal, C::Group],
                &[C::Principal, C::Group, C::AdStructure, C::Host],
            ),
            WriteOwner => r(
                &[C::Principal, C::Group],
                &[C::Principal, C::Group, C::AdStructure],
            ),
            AllExtendedRights => r(
                &[C::Principal, C::Group],
                &[C::Principal, C::Group, C::AdStructure],
            ),
            WriteGpLink => EdgeRule {
                src_classes: &[C::Principal, C::Group],
                dst_classes: NO_C,
                src_kinds: NO_K,
                dst_kinds: &[K::OrganizationalUnit, K::Domain],
            },
            AddSelf => r(&[C::Principal, C::Group], &[C::Group]),

            UnconstrainedDelegation => EdgeRule {
                src_classes: &[C::Host],
                dst_classes: NO_C,
                src_kinds: &[K::ComputerAccount],
                dst_kinds: &[K::Domain],
            },
            CanKerberoast => r(&[C::Principal, C::Group], &[C::Principal]),
            CanAsrepRoast => r(&[C::Principal, C::Group], &[C::Principal]),

            Enroll => EdgeRule {
                src_classes: &[C::Principal, C::Group],
                dst_classes: NO_C,
                src_kinds: NO_K,
                dst_kinds: &[K::CertTemplate],
            },
            EnrollOnBehalfOf => EdgeRule {
                src_classes: &[C::Principal, C::Group],
                dst_classes: NO_C,
                src_kinds: NO_K,
                dst_kinds: &[K::CertTemplate],
            },
            PublishedTo => rk(&[K::CertTemplate], &[K::CertificateAuthority]),
            AuthenticatesAs => EdgeRule {
                src_classes: NO_C,
                dst_classes: &[C::Principal],
                src_kinds: &[K::CertTemplate, K::CertificateAuthority],
                dst_kinds: &[K::Domain],
            },

            GpoAppliesTo => EdgeRule {
                src_classes: NO_C,
                dst_classes: &[C::Host, C::Principal, C::Group],
                src_kinds: &[K::Gpo],
                dst_kinds: NO_K,
            },

            SqlLink => r(&[C::Service], &[C::Service]),
            RelayTo => EdgeRule {
                src_classes: &[C::Host, C::Service, C::Principal],
                dst_classes: &[C::Host, C::Service],
                src_kinds: NO_K,
                dst_kinds: &[K::CertificateAuthority],
            },

            HostedOn => EdgeRule {
                src_classes: NO_C,
                dst_classes: &[C::Service, C::Host],
                src_kinds: &[K::WebApplication],
                dst_kinds: NO_K,
            },

            Affects => EdgeRule {
                src_classes: NO_C,
                dst_classes: &[
                    C::Host,
                    C::Service,
                    C::Principal,
                    C::Group,
                    C::AdStructure,
                    C::Cloud,
                ],
                src_kinds: &[K::Finding],
                dst_kinds: NO_K,
            },
            LootedFrom => EdgeRule {
                src_classes: NO_C,
                dst_classes: &[C::Host, C::Principal],
                src_kinds: &[K::Loot],
                dst_kinds: NO_K,
            },
            YieldsCredential => EdgeRule {
                src_classes: NO_C,
                dst_classes: &[C::Principal],
                src_kinds: &[K::Loot],
                dst_kinds: NO_K,
            },
            EvidenceFor => EdgeRule {
                src_classes: NO_C,
                dst_classes: &[
                    C::Host,
                    C::Service,
                    C::Principal,
                    C::Group,
                    C::AdStructure,
                    C::Cloud,
                ],
                src_kinds: &[K::Loot],
                dst_kinds: NO_K,
            },

            Custom => r(NO_C, NO_C),
        }
    }

    pub fn permits(self, src: NodeKind, dst: NodeKind) -> bool {
        if self == EdgeKind::Custom {
            return true;
        }
        let r = self.rule();
        let src_ok = r.src_classes.contains(&src.class()) || r.src_kinds.contains(&src);
        let dst_ok = r.dst_classes.contains(&dst.class()) || r.dst_kinds.contains(&dst);
        src_ok && dst_ok
    }

    pub fn permitted_between(src: NodeKind, dst: NodeKind) -> Vec<EdgeKind> {
        ALL_EDGE_KINDS
            .iter()
            .copied()
            .filter(|k| k.permits(src, dst))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::EdgeKind;
    use crate::node::NodeKind::*;

    #[test]
    fn arrays_match_enum_cardinality() {
        assert_eq!(
            ALL_NODE_KINDS.len(),
            30,
            "add new NodeKind to ALL_NODE_KINDS"
        );
        assert_eq!(
            ALL_EDGE_KINDS.len(),
            64,
            "add new EdgeKind to ALL_EDGE_KINDS"
        );
    }

    #[test]
    fn hosts_vm_is_hypervisor_to_vm_only() {
        assert!(EdgeKind::HostsVm.permits(Hypervisor, VirtualMachine));
        assert!(!EdgeKind::HostsVm.permits(HostLinux, VirtualMachine));
        assert!(!EdgeKind::HostsVm.permits(Hypervisor, HostWindows));
    }

    #[test]
    fn trusts_is_domain_to_domain_only() {
        assert!(EdgeKind::Trusts.permits(Domain, Domain));
        assert!(EdgeKind::Trusts.permits(Forest, Domain));
        assert!(!EdgeKind::Trusts.permits(HostWindows, Domain));
    }

    #[test]
    fn listens_on_is_service_to_host() {
        assert!(EdgeKind::ListensOn.permits(Service, HostWindows));
        assert!(!EdgeKind::ListensOn.permits(HostWindows, Service));
    }

    #[test]
    fn dc_for_is_dc_to_domain() {
        assert!(EdgeKind::DcFor.permits(DomainController, Domain));
        assert!(!EdgeKind::DcFor.permits(HostWindows, Domain));
    }

    #[test]
    fn admin_to_spans_principals_onto_hosts() {
        assert!(EdgeKind::AdminTo.permits(UserAccount, HostWindows));
        assert!(EdgeKind::AdminTo.permits(Group, DomainController));
        assert!(!EdgeKind::AdminTo.permits(HostWindows, UserAccount));
    }

    #[test]
    fn custom_permits_anything() {
        assert!(EdgeKind::Custom.permits(Service, Domain));
        assert!(EdgeKind::Custom.permits(CloudIdentity, Vlan));
    }

    #[test]
    fn permitted_between_filters_to_sensible_kinds() {
        let hv_vm = EdgeKind::permitted_between(Hypervisor, VirtualMachine);
        assert!(hv_vm.contains(&EdgeKind::HostsVm));
        assert!(!hv_vm.contains(&EdgeKind::ListensOn));
        assert!(hv_vm.contains(&EdgeKind::Custom));
    }

    #[test]
    fn no_edge_kind_panics_on_rule() {
        for k in ALL_EDGE_KINDS {
            let _ = k.permits(HostWindows, HostWindows);
        }
    }

    fn s<T: Serialize>(t: &T) -> String {
        serde_json::to_value(t)
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned()
    }
    fn sorted(mut v: Vec<String>) -> Vec<String> {
        v.sort();
        v
    }

    fn build_contract() -> serde_json::Value {
        let node_classes: serde_json::Map<String, serde_json::Value> = ALL_NODE_KINDS
            .iter()
            .map(|k| (s(k), serde_json::Value::String(s(&k.class()))))
            .collect();
        let edge_rules: serde_json::Map<String, serde_json::Value> = ALL_EDGE_KINDS
            .iter()
            .map(|k| {
                let r = k.rule();
                let v = serde_json::json!({
                    "src_classes": sorted(r.src_classes.iter().map(s).collect()),
                    "dst_classes": sorted(r.dst_classes.iter().map(s).collect()),
                    "src_kinds": sorted(r.src_kinds.iter().map(s).collect()),
                    "dst_kinds": sorted(r.dst_kinds.iter().map(s).collect()),
                });
                (s(k), v)
            })
            .collect();
        serde_json::json!({ "node_classes": node_classes, "edge_rules": edge_rules })
    }

    #[test]
    fn edge_matrix_fixture() {
        let built = build_contract();
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/edge_matrix.json"
        );
        if std::env::var("UPDATE_EDGE_FIXTURE").is_ok() {
            std::fs::create_dir_all(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"))
                .unwrap();
            std::fs::write(path, serde_json::to_string_pretty(&built).unwrap()).unwrap();
            return;
        }
        let committed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("fixture exists")).unwrap();
        assert_eq!(
            built, committed,
            "constraint table changed. regenerate with UPDATE_EDGE_FIXTURE=1 and mirror in catalog.ts"
        );
    }
}
