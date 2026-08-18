from __future__ import annotations

from bugslyce.core.models import PortService
import bugslyce.parsers.nmap as nmap_parser


def _service(
    *,
    port: int,
    service: str,
    protocol: str = "tcp",
    state: str = "open",
) -> PortService:
    return PortService(
        host="example.test",
        port=port,
        protocol=protocol,
        state=state,
        service=service,
        product=None,
        version=None,
        source_file="nmap-services-all.txt",
        evidence_ids=[f"EVID-PORT-{port}"],
        tags=[],
    )


def test_smb_capability_uses_service_evidence_on_arbitrary_tcp_ports() -> None:
    assert nmap_parser.is_smb_capable_port_service(
        _service(port=1445, service="microsoft-ds")
    )
    assert nmap_parser.is_smb_capable_port_service(
        _service(port=31337, service="netbios-ssn")
    )


def test_conventional_smb_port_without_smb_service_evidence_is_not_eligible() -> None:
    assert not nmap_parser.is_smb_capable_port_service(
        _service(port=445, service="http")
    )
    assert not nmap_parser.is_smb_capable_port_service(
        _service(port=139, service="ssh")
    )


def test_smb_capability_requires_open_tcp_service() -> None:
    assert not nmap_parser.is_smb_capable_port_service(
        _service(port=445, service="microsoft-ds", state="closed")
    )
    assert not nmap_parser.is_smb_capable_port_service(
        _service(port=445, service="microsoft-ds", protocol="udp")
    )


def test_smb_target_selection_aggregates_duplicate_retained_evidence() -> None:
    from importlib import import_module

    smb_eligibility = import_module("bugslyce.recon.smb_eligibility")

    first = PortService(
        host="files.example.test",
        port=1445,
        protocol="tcp",
        state="open",
        service="microsoft-ds",
        product="Samba smbd",
        version="4.x",
        source_file="nmap-allports.txt",
        evidence_ids=["EVID-PORT-0001"],
        tags=[],
    )
    second = PortService(
        host="files.example.test",
        port=1445,
        protocol="tcp",
        state="open",
        service="microsoft-ds",
        product="Samba smbd",
        version="4.x",
        source_file="nmap-services-all.txt",
        evidence_ids=["EVID-PORT-0009", "EVID-PORT-0001"],
        tags=[],
    )

    expected = (
        (
            "files.example.test",
            1445,
            ("microsoft-ds",),
            ("EVID-PORT-0001", "EVID-PORT-0009"),
            ("nmap-allports.txt", "nmap-services-all.txt"),
        ),
    )

    for records in ((first, second), (second, first)):
        targets = smb_eligibility.select_smb_enumeration_targets(records)

        assert tuple(
            (
                item.host,
                item.port,
                item.service_names,
                item.evidence_ids,
                item.source_files,
            )
            for item in targets
        ) == expected


def test_smb_target_selection_preserves_distinct_arbitrary_smb_ports() -> None:
    from importlib import import_module

    smb_eligibility = import_module("bugslyce.recon.smb_eligibility")

    targets = smb_eligibility.select_smb_enumeration_targets(
        (
            _service(port=445, service="microsoft-ds"),
            _service(port=31337, service="netbios-ssn"),
            _service(port=1445, service="microsoft-ds"),
        )
    )

    assert tuple((item.host, item.port) for item in targets) == (
        ("example.test", 445),
        ("example.test", 1445),
        ("example.test", 31337),
    )


def test_smb_target_selection_returns_no_work_for_non_smb_services() -> None:
    from importlib import import_module

    smb_eligibility = import_module("bugslyce.recon.smb_eligibility")

    targets = smb_eligibility.select_smb_enumeration_targets(
        (
            _service(port=445, service="http"),
            _service(port=139, service="ssh"),
            _service(port=9000, service="microsoft-ds", state="closed"),
            _service(port=9001, service="microsoft-ds", protocol="udp"),
        )
    )

    assert targets == ()


def test_smb_target_selection_recovers_all_reconciled_trigger_source_files(
    tmp_path,
) -> None:
    from bugslyce.core.project import build_project_state
    from bugslyce.recon.smb_eligibility import select_smb_enumeration_targets

    (tmp_path / "nmap-allports.txt").write_text(
        "Nmap scan report for files.example.test\n"
        "PORT      STATE SERVICE\n"
        "31337/tcp open  microsoft-ds\n",
        encoding="utf-8",
    )
    (tmp_path / "nmap-services-all.txt").write_text(
        "Nmap scan report for files.example.test\n"
        "PORT      STATE SERVICE      VERSION\n"
        "31337/tcp open  microsoft-ds Samba smbd 4.19\n",
        encoding="utf-8",
    )

    state = build_project_state(tmp_path)

    assert len(state.port_services) == 1
    assert len(state.port_services[0].evidence_ids) == 2

    targets = select_smb_enumeration_targets(
        state.port_services,
        state.evidence,
    )

    assert len(targets) == 1
    assert targets[0].port == 31337
    assert tuple(
        sorted(path.rsplit("/", 1)[-1] for path in targets[0].source_files)
    ) == (
        "nmap-allports.txt",
        "nmap-services-all.txt",
    )
