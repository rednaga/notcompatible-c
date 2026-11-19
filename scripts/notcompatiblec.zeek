##! Loads notcompatiblec.sig and raises a Notice with useful triage context
##! when it fires, instead of leaving the hit buried in signatures.log.
##!
##! Validated on Zeek 9.0.1 against a synthetic pcap (not real captured
##! traffic or real NotCompatible.C samples) -- parses and loads cleanly in
##! `zeek -a` (parse-only) and `zeek -C -r`, correctly raises
##! Possible_Handshake on 5/5 expected hits with 0 false positives across 260
##! should-not-match connections (60 explicit cases + 200 random binary
##! payloads). See notcompatiblec.sig for what the signature does and does
##! not prove, and for test details.
##!
##! Usage:
##!   zeek -r some.pcap scripts/notcompatiblec.zeek
##! or drop both files next to local.zeek and:
##!   @load ./notcompatiblec
##!
##! Each hit also raises Zeek's own Signatures::Sensitive_Signature notice
##! (and a signatures.log row) in addition to Possible_Handshake below. To
##! silence the built-in one and keep only this module's notice, add:
##!   redef Signatures::ignored_ids += /notcompatiblec-client-pubkey/;

@load-sigs ./notcompatiblec.sig

module NotCompatibleC;

export {
    redef enum Notice::Type += {
        ## Fired when a connection's first originator-side bytes match the
        ## bot's key-exchange framing (see notcompatiblec.sig). This is a
        ## passive heuristic on a dynamic-length field Zeek's signature
        ## language can't fully validate -- confirm with an active probe
        ## (notcompatiblec.nse / zmap_verify.py) before treating it as real.
        Possible_Handshake
    };
}

event signature_match(state: signature_state, msg: string, data: string)
{
    if (state$sig_id != "notcompatiblec-client-pubkey")
        return;

    NOTICE([$note=Possible_Handshake,
            $msg=fmt("possible NotCompatible.C key-exchange from %s to %s:%s "
                      + "(unconfirmed -- verify with notcompatiblec.nse or "
                      + "zmap_verify.py before acting on this)",
                      state$conn$id$orig_h, state$conn$id$resp_h, state$conn$id$resp_p),
            $conn=state$conn,
            $identifier=cat(state$conn$id$orig_h, state$conn$id$resp_h, state$conn$id$resp_p)]);
}
