"""RED contract for normalized SMB and network-service composition."""

from __future__ import annotations

from dataclasses import fields
from inspect import signature

import pytest

from bugslyce.core.models import Evidence, PortService, ProjectState, SMBShare
from bugslyce.reports.operator_brief import (
    OperatorBriefFactKind,
    OperatorBriefFactRole,
    OperatorBriefSemanticClass,
    OperatorBriefSubjectKind,
)


def _api():
    from bugslyce.reports.operator_brief_network import (
        OperatorBriefNetworkComposition,
        OperatorBriefNetworkCompositionInput,
        OperatorBriefNetworkSubject,
        OperatorBriefServiceObservation,
        OperatorBriefSmbShareObservation,
        build_operator_brief_network_inputs_from_project_state,
        build_operator_brief_service_observation,
        build_operator_brief_smb_share_observation,
        combine_operator_brief_network_inputs,
        compose_operator_brief_network,
    )

    return locals()


def _share(
    *,
    host: str = "files.example.test",
    port: int = 445,
    name: str = "nt4wrksv",
    share_type: str = "Disk",
    comment: str = "Retained share",
    evidence_ids: list[str] | None = None,
    source_file: str = "smb-shares-files.example.test-445.txt",
) -> SMBShare:
    return SMBShare(
        host=host,
        port=port,
        share_name=name,
        share_type=share_type,
        comment=comment,
        source_file=source_file,
        trigger_service_names=["microsoft-ds"],
        trigger_evidence_ids=["EVID-PORT-SMB"],
        trigger_source_files=["nmap-services-all.txt"],
        evidence_ids=evidence_ids or ["EVID-SMB-0004"],
        tags=[],
    )


def _service(
    *,
    host: str = "files.example.test",
    port: int = 445,
    protocol: str = "tcp",
    state: str = "open",
    service: str | None = "microsoft-ds",
    product: str | None = None,
    version: str | None = None,
    evidence_ids: list[str] | None = None,
    source_file: str = "nmap-services-all.txt",
    tags: list[str] | None = None,
) -> PortService:
    return PortService(
        host=host,
        port=port,
        protocol=protocol,
        state=state,
        service=service,
        product=product,
        version=version,
        source_file=source_file,
        evidence_ids=evidence_ids or ["EVID-PORT-SMB"],
        tags=tags or [],
    )


def _state(
    *,
    shares: tuple[SMBShare, ...] = (),
    services: tuple[PortService, ...] = (),
) -> ProjectState:
    evidence_by_id: dict[str, Evidence] = {}
    for share in shares:
        for evidence_id in share.evidence_ids:
            evidence_by_id[evidence_id] = Evidence(
                evidence_id,
                share.source_file,
                "smb_share",
                share.share_name,
                {"host": share.host, "port": share.port},
            )
    for service in services:
        for evidence_id in service.evidence_ids:
            evidence_by_id[evidence_id] = Evidence(
                evidence_id,
                service.source_file,
                "port_service",
                f"{service.host}:{service.port}/{service.protocol}",
                {"state": service.state, "service": service.service},
            )
    return ProjectState(
        project_name="network-composition",
        input_dir="/live/project",
        processed_files=[],
        scope_summary="example.test",
        assets=[],
        http_services=[],
        endpoints=[],
        port_services=list(services),
        http_artifacts=[],
        discovered_paths=[],
        recon_summary=None,
        recon_manifest=None,
        evidence=list(evidence_by_id.values()),
        warnings=[],
        generated_at="2026-08-22T12:00:00Z",
        smb_shares=list(shares),
    )


def _inputs(api, state: ProjectState):
    return api["build_operator_brief_network_inputs_from_project_state"](state)


def _composition(api, state: ProjectState):
    return api["compose_operator_brief_network"](_inputs(api, state))


def _facts(composition, kind: OperatorBriefFactKind):
    return tuple(fact for fact in composition.facts if fact.kind is kind)


def test_network_api_is_a_separate_normalized_composition_boundary() -> None:
    api = _api()

    assert set(api) >= {
        "OperatorBriefSmbShareObservation",
        "OperatorBriefServiceObservation",
        "OperatorBriefNetworkCompositionInput",
        "OperatorBriefNetworkSubject",
        "OperatorBriefNetworkComposition",
        "build_operator_brief_smb_share_observation",
        "build_operator_brief_service_observation",
        "build_operator_brief_network_inputs_from_project_state",
        "combine_operator_brief_network_inputs",
        "compose_operator_brief_network",
    }


def test_network_adapter_accepts_only_project_state() -> None:
    api = _api()
    parameters = signature(
        api["build_operator_brief_network_inputs_from_project_state"]
    ).parameters

    assert tuple(parameters) == ("project_state",)


def test_normalized_builder_signatures_are_storage_agnostic() -> None:
    api = _api()

    assert tuple(
        signature(api["build_operator_brief_smb_share_observation"]).parameters
    ) == (
        "source_kind",
        "source_id",
        "host",
        "port",
        "share_name",
        "share_type",
        "comment",
        "trigger_service_names",
        "trigger_evidence_ids",
        "trigger_artefact_references",
        "evidence_ids",
        "artefact_references",
    )
    assert tuple(
        signature(api["build_operator_brief_service_observation"]).parameters
    ) == (
        "source_kind",
        "source_id",
        "host",
        "port",
        "protocol",
        "state",
        "service",
        "product",
        "version",
        "http_capable",
        "evidence_ids",
        "artefact_references",
    )


def test_one_smb_share_becomes_observed_direct_smb_fact() -> None:
    api = _api()
    composition = _composition(api, _state(shares=(_share(),)))
    facts = _facts(composition, OperatorBriefFactKind.SMB_SHARE)

    assert len(facts) == 1
    assert facts[0].semantic_class is OperatorBriefSemanticClass.OBSERVED
    assert facts[0].role is OperatorBriefFactRole.DIRECT_EVIDENCE
    assert facts[0].share_name == "nt4wrksv"
    assert facts[0].share_type == "Disk"


def test_multiple_shares_on_one_host_and_port_form_one_smb_surface() -> None:
    api = _api()
    composition = _composition(
        api,
        _state(shares=(_share(name="nt4wrksv"), _share(name="public"))),
    )

    assert len(composition.subjects) == 1
    assert composition.subjects[0].subject_kind is OperatorBriefSubjectKind.SMB_SURFACE
    assert {fact.share_name for fact in composition.facts} == {"nt4wrksv", "public"}


def test_same_share_name_on_different_hosts_remains_separate() -> None:
    api = _api()
    composition = _composition(
        api,
        _state(
            shares=(
                _share(host="first.example.test"),
                _share(host="second.example.test"),
            )
        ),
    )

    assert len(composition.subjects) == 2
    assert len({subject.subject_id for subject in composition.subjects}) == 2


def test_smb_input_order_is_deterministic() -> None:
    api = _api()
    shares = (_share(name="engineering"), _share(name="backups"))

    assert _composition(api, _state(shares=shares)) == _composition(
        api, _state(shares=tuple(reversed(shares)))
    )


def test_smb_identity_ignores_provenance_enrichment() -> None:
    api = _api()
    first = _inputs(api, _state(shares=(_share(),))).smb_shares[0]
    enriched = _inputs(
        api,
        _state(
            shares=(
                _share(
                    evidence_ids=["EVID-SMB-OTHER"],
                    source_file="smb-shares-copy.txt",
                ),
            )
        ),
    ).smb_shares[0]

    assert first.observation_id == enriched.observation_id


def test_duplicate_smb_semantics_union_provenance() -> None:
    api = _api()
    first = _inputs(api, _state(shares=(_share(),)))
    second = _inputs(
        api,
        _state(
            shares=(
                _share(
                    evidence_ids=["EVID-SMB-OTHER"],
                    source_file="smb-shares-copy.txt",
                ),
            )
        ),
    )

    combined = api["combine_operator_brief_network_inputs"](first, second)

    assert len(combined.smb_shares) == 1
    assert combined.smb_shares[0].evidence_ids == (
        "EVID-SMB-0004",
        "EVID-SMB-OTHER",
    )
    assert combined.smb_shares[0].artefact_references == (
        "smb-shares-copy.txt",
        "smb-shares-files.example.test-445.txt",
    )


def test_smb_authoritative_type_comment_and_trigger_context_are_preserved() -> None:
    api = _api()
    observation = _inputs(api, _state(shares=(_share(),))).smb_shares[0]

    assert observation.share_type == "Disk"
    assert observation.comment == "Retained share"
    assert observation.trigger_service_names == ("microsoft-ds",)
    assert observation.trigger_evidence_ids == ("EVID-PORT-SMB",)
    assert observation.trigger_artefact_references == ("nmap-services-all.txt",)


def test_smb_fact_does_not_claim_access_writeability_or_vulnerability() -> None:
    api = _api()
    fact = _facts(
        _composition(api, _state(shares=(_share(),))),
        OperatorBriefFactKind.SMB_SHARE,
    )[0]
    rendered = f"{fact.label} {fact.summary}".casefold()

    assert not {"writable", "anonymous", "exploitable", "vulnerable"} & set(
        rendered.split()
    )


def test_empty_smb_input_produces_no_smb_fact_or_subject() -> None:
    api = _api()
    composition = _composition(api, _state())

    assert not _facts(composition, OperatorBriefFactKind.SMB_SHARE)
    assert not composition.subjects


def test_invalid_smb_source_fails_closed() -> None:
    api = _api()

    with pytest.raises(ValueError):
        _inputs(api, _state(shares=(_share(host=""),)))


def test_relevant_shaped_share_remains_specific_and_visible() -> None:
    api = _api()
    fact = _facts(
        _composition(api, _state(shares=(_share(name="nt4wrksv"),))),
        OperatorBriefFactKind.SMB_SHARE,
    )[0]

    assert fact.share_name == "nt4wrksv"
    assert fact.evidence_ids == ("EVID-SMB-0004",)


def test_one_non_http_service_becomes_observed_direct_service_fact() -> None:
    api = _api()
    fact = _facts(
        _composition(
            api,
            _state(services=(_service(port=22, service="ssh"),)),
        ),
        OperatorBriefFactKind.SERVICE,
    )[0]

    assert fact.semantic_class is OperatorBriefSemanticClass.OBSERVED
    assert fact.role is OperatorBriefFactRole.DIRECT_EVIDENCE
    assert fact.service == "ssh"


def test_multiple_ports_on_one_host_remain_distinct_service_surfaces() -> None:
    api = _api()
    composition = _composition(
        api,
        _state(
            services=(
                _service(port=22, service="ssh"),
                _service(port=25, service="smtp"),
            )
        ),
    )

    assert len(composition.subjects) == 2
    assert {subject.ports for subject in composition.subjects} == {(22,), (25,)}


def test_same_service_on_different_hosts_remains_distinct() -> None:
    api = _api()
    composition = _composition(
        api,
        _state(
            services=(
                _service(host="first.example.test", port=22, service="ssh"),
                _service(host="second.example.test", port=22, service="ssh"),
            )
        ),
    )

    assert len(composition.subjects) == 2


def test_service_transport_protocol_is_semantic() -> None:
    api = _api()
    inputs = _inputs(
        api,
        _state(
            services=(
                _service(port=53, protocol="tcp", service="domain"),
                _service(port=53, protocol="udp", service="domain"),
            )
        ),
    )

    assert {item.protocol for item in inputs.services} == {"tcp", "udp"}
    assert len({item.observation_id for item in inputs.services}) == 2


def test_service_product_and_version_are_retained_as_observation_context() -> None:
    api = _api()
    observation = _inputs(
        api,
        _state(
            services=(
                _service(
                    port=22,
                    service="ssh",
                    product="OpenSSH",
                    version="9.0",
                ),
            )
        ),
    ).services[0]

    assert (observation.product, observation.version) == ("OpenSSH", "9.0")


def test_service_version_does_not_create_vulnerability_claim() -> None:
    api = _api()
    fact = _facts(
        _composition(
            api,
            _state(
                services=(
                    _service(
                        port=22,
                        service="ssh",
                        product="OpenSSH",
                        version="9.0",
                    ),
                )
            ),
        ),
        OperatorBriefFactKind.SERVICE,
    )[0]

    assert "vulnerab" not in f"{fact.label} {fact.summary}".casefold()
    assert "exploit" not in f"{fact.label} {fact.summary}".casefold()


def test_service_order_and_identity_ignore_provenance_order() -> None:
    api = _api()
    services = (
        _service(port=22, service="ssh"),
        _service(port=25, service="smtp"),
    )

    assert _composition(api, _state(services=services)) == _composition(
        api, _state(services=tuple(reversed(services)))
    )


def test_duplicate_service_semantics_union_evidence_and_artefacts() -> None:
    api = _api()
    first = _inputs(api, _state(services=(_service(port=22, service="ssh"),)))
    second = _inputs(
        api,
        _state(
            services=(
                _service(
                    port=22,
                    service="ssh",
                    evidence_ids=["EVID-SSH-OTHER"],
                    source_file="nmap-copy.txt",
                ),
            )
        ),
    )
    combined = api["combine_operator_brief_network_inputs"](first, second)

    assert len(combined.services) == 1
    assert combined.services[0].evidence_ids == (
        "EVID-PORT-SMB",
        "EVID-SSH-OTHER",
    )
    assert combined.services[0].artefact_references == (
        "nmap-copy.txt",
        "nmap-services-all.txt",
    )


def test_empty_service_input_is_empty_and_sparse_service_is_representable() -> None:
    api = _api()
    empty = _composition(api, _state())
    sparse = _composition(
        api,
        _state(services=(_service(port=22, service="ssh"),)),
    )

    assert not _facts(empty, OperatorBriefFactKind.SERVICE)
    assert len(sparse.subjects) == 1


def test_http_capable_port_service_remains_service_context_not_http_response() -> None:
    api = _api()
    inputs = _inputs(
        api,
        _state(
            services=(
                _service(
                    port=8080,
                    service="http",
                    tags=["http_service"],
                ),
            )
        ),
    )
    composition = api["compose_operator_brief_network"](inputs)

    assert inputs.services[0].http_capable is True
    assert {fact.kind for fact in composition.facts} == {
        OperatorBriefFactKind.SERVICE
    }


def test_duplicate_project_state_service_rows_do_not_duplicate_facts() -> None:
    api = _api()
    service = _service(port=22, service="ssh")
    composition = _composition(api, _state(services=(service, service)))

    assert len(_facts(composition, OperatorBriefFactKind.SERVICE)) == 1


def test_smb_share_and_matching_smb_service_form_one_coherent_surface() -> None:
    api = _api()
    composition = _composition(
        api,
        _state(shares=(_share(),), services=(_service(),)),
    )

    assert len(composition.subjects) == 1
    subject = composition.subjects[0]
    assert subject.subject_kind is OperatorBriefSubjectKind.SMB_SURFACE
    assert len(subject.smb_share_observation_ids) == 1
    assert len(subject.service_observation_ids) == 1
    assert {fact.kind for fact in composition.facts} == {
        OperatorBriefFactKind.SMB_SHARE,
        OperatorBriefFactKind.SERVICE,
    }


def test_smb_share_does_not_absorb_smb_service_on_another_host() -> None:
    api = _api()
    composition = _composition(
        api,
        _state(
            shares=(_share(host="shares.example.test"),),
            services=(_service(host="other.example.test"),),
        ),
    )

    assert len(composition.subjects) == 2
    assert {item.subject_kind for item in composition.subjects} == {
        OperatorBriefSubjectKind.SMB_SURFACE,
        OperatorBriefSubjectKind.SERVICE_SURFACE,
    }


def test_specific_share_fact_remains_visible_with_generic_smb_service() -> None:
    api = _api()
    composition = _composition(
        api,
        _state(shares=(_share(),), services=(_service(),)),
    )

    assert _facts(composition, OperatorBriefFactKind.SMB_SHARE)[0].share_name == (
        "nt4wrksv"
    )


def test_shared_smb_and_service_provenance_is_deduplicated_at_subject() -> None:
    api = _api()
    composition = _composition(
        api,
        _state(shares=(_share(),), services=(_service(),)),
    )

    assert composition.subjects[0].evidence_ids.count("EVID-PORT-SMB") == 1
    assert composition.subjects[0].artefact_references.count(
        "nmap-services-all.txt"
    ) == 1


def test_network_models_store_no_rank_disposition_or_thread_score() -> None:
    api = _api()
    public_models = (
        api["OperatorBriefSmbShareObservation"],
        api["OperatorBriefServiceObservation"],
        api["OperatorBriefNetworkSubject"],
        api["OperatorBriefNetworkComposition"],
    )

    for model in public_models:
        names = {item.name for item in fields(model)}
        assert not names & {
            "rank",
            "signal",
            "score",
            "disposition",
            "why_review",
            "next_review_step",
        }


def test_live_logical_source_references_are_not_pack_rewritten() -> None:
    api = _api()
    inputs = _inputs(api, _state(shares=(_share(),), services=(_service(),)))
    references = {
        reference
        for observation in (*inputs.smb_shares, *inputs.services)
        for reference in observation.artefact_references
    }

    assert "smb-shares-files.example.test-445.txt" in references
    assert "nmap-services-all.txt" in references
    assert not any(reference.startswith("raw/") for reference in references)


def test_project_local_absolute_sources_become_live_logical_references() -> None:
    api = _api()
    inputs = _inputs(
        api,
        _state(
            shares=(
                _share(
                    source_file=(
                        "/live/project/smb-shares-files.example.test-445.txt"
                    )
                ),
            ),
            services=(
                _service(source_file="/live/project/nmap-services-all.txt"),
            ),
        ),
    )
    references = {
        reference
        for observation in (*inputs.smb_shares, *inputs.services)
        for reference in observation.artefact_references
    }

    assert references == {
        "smb-shares-files.example.test-445.txt",
        "nmap-services-all.txt",
    }
    assert not any(reference.startswith("/") for reference in references)


def test_operator_brief_schema_already_supports_network_fact_and_subject_kinds() -> None:
    assert OperatorBriefFactKind.SMB_SHARE.value == "smb_share"
    assert OperatorBriefFactKind.SERVICE.value == "service"
    assert OperatorBriefSubjectKind.SMB_SURFACE.value == "smb_surface"
    assert OperatorBriefSubjectKind.SERVICE_SURFACE.value == "service_surface"


def test_composition_resolves_smb_member_to_normalized_observation() -> None:
    api = _api()
    share = SMBShare(
        host="closure.example.test",
        port=445,
        share_name="archive",
        share_type="Disk",
        comment="Distinct retained comment",
        source_file="smb-closure.txt",
        trigger_service_names=["microsoft-ds", "netbios-ssn"],
        trigger_evidence_ids=["EVID-TRIGGER-CLOSURE"],
        trigger_source_files=["nmap-trigger-closure.txt"],
        evidence_ids=["EVID-SMB-CLOSURE"],
        tags=[],
    )

    composition = _composition(api, _state(shares=(share,)))
    subject = composition.subjects[0]
    observations = {
        observation.observation_id: observation
        for observation in composition.smb_shares
    }
    observation = observations[subject.smb_share_observation_ids[0]]

    assert observation.comment == "Distinct retained comment"
    assert observation.trigger_service_names == ("microsoft-ds", "netbios-ssn")
    assert observation.trigger_evidence_ids == ("EVID-TRIGGER-CLOSURE",)
    assert observation.trigger_artefact_references == (
        "nmap-trigger-closure.txt",
    )
    assert observation.evidence_ids == ("EVID-SMB-CLOSURE",)
    assert observation.artefact_references == ("smb-closure.txt",)
    fact = _facts(composition, OperatorBriefFactKind.SMB_SHARE)[0]
    assert fact.evidence_ids == ("EVID-SMB-CLOSURE",)
    assert fact.artefact_references == ("smb-closure.txt",)


def test_composition_resolves_service_member_to_normalized_observation() -> None:
    api = _api()
    service = _service(
        host="closure.example.test",
        port=8080,
        state="filtered",
        service="http-proxy",
        product="Closure Proxy",
        version="7.4",
        evidence_ids=["EVID-SERVICE-CLOSURE"],
        source_file="nmap-service-closure.txt",
        tags=["http_service"],
    )

    composition = _composition(api, _state(services=(service,)))
    subject = composition.subjects[0]
    observations = {
        observation.observation_id: observation
        for observation in composition.services
    }
    observation = observations[subject.service_observation_ids[0]]

    assert observation.host == "closure.example.test"
    assert observation.port == 8080
    assert observation.protocol == "tcp"
    assert observation.state == "filtered"
    assert observation.service == "http-proxy"
    assert observation.product == "Closure Proxy"
    assert observation.version == "7.4"
    assert observation.http_capable is True
    assert observation.evidence_ids == ("EVID-SERVICE-CLOSURE",)
    assert observation.artefact_references == ("nmap-service-closure.txt",)
    assert len(_facts(composition, OperatorBriefFactKind.SERVICE)) == 1


def test_composition_member_ids_have_complete_referential_integrity() -> None:
    api = _api()
    composition = _composition(
        api,
        _state(
            shares=(_share(),),
            services=(
                _service(),
                _service(port=22, service="ssh"),
            ),
        ),
    )
    smb_ids = tuple(
        observation.observation_id for observation in composition.smb_shares
    )
    service_ids = tuple(
        observation.observation_id for observation in composition.services
    )

    assert len(smb_ids) == len(set(smb_ids))
    assert len(service_ids) == len(set(service_ids))
    for subject in composition.subjects:
        assert all(
            smb_ids.count(member_id) == 1
            for member_id in subject.smb_share_observation_ids
        )
        assert all(
            service_ids.count(member_id) == 1
            for member_id in subject.service_observation_ids
        )
