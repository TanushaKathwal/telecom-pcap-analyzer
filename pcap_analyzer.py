import pyshark
import os
from collections import Counter
from collections import defaultdict
from pyshark.capture.capture import TSharkCrashException

def parse_size(size_text):
    if not size_text:
        return 1024 ** 3

    text = size_text.strip().upper().replace(" ", "")
    units = {
        "B": 1,
        "KB": 1024,
        "MB": 1024 ** 2,
        "GB": 1024 ** 3,
        "TB": 1024 ** 4,
    }

    for unit in ("TB", "GB", "MB", "KB", "B"):
        if text.endswith(unit):
            number = text[:-len(unit)]
            return int(float(number) * units[unit])

    return int(float(text))


def format_size(num_bytes):
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(num_bytes)

    for unit in units:
        if size < 1024 or unit == "TB":
            return f"{size:.2f} {unit}"
        size /= 1024

def safe_get_attr(obj, attr_names):
    for name in attr_names:
        try:
            if hasattr(obj, name):
                value = getattr(obj, name)
                if value is not None and str(value).strip() != "":
                    return str(value)
        except Exception:
            pass
    return None

def get_protocol_layer(pkt, protocol):
    try:
        if hasattr(pkt, protocol):
            return getattr(pkt, protocol)
    except Exception:
        pass
    return None

def get_pdu_type(pkt, protocol):
    try:
        layer = get_protocol_layer(pkt, protocol)
        if layer is None:
            return None

        fields = [f.lower() for f in getattr(layer, "field_names", [])]

        if "initiatingmessage_element" in fields:
            return "request"
        elif "successfuloutcome_element" in fields:
            return "response"
        elif "unsuccessfuloutcome_element" in fields:
            return "failure"
    except Exception:
        pass

    return None


def get_transaction_key(pkt, protocol):
    try:
        layer = get_protocol_layer(pkt, protocol)
        if layer is None:
            return None

        if protocol == "xnap":
            transaction_id = safe_get_attr(layer, ["TransactionID", "transactionID", "transactionid"])
            source_ue = safe_get_attr(layer, ["SourceNGRANNodeUEXnAPID", "sourceNGRANNodeUEXnAPID", "source_ng_ran_node_ue_xnap_id"])
            target_ue = safe_get_attr(layer, ["TargetNGRANNodeUEXnAPID", "targetNGRANNodeUEXnAPID", "target_ng_ran_node_ue_xnap_id"])

            if transaction_id or source_ue or target_ue:
                return f"xnap|{transaction_id}|{source_ue}|{target_ue}"

        elif protocol == "ngap":
            amf_ue = safe_get_attr(layer, ["AMF_UE_NGAP_ID", "aMF_UE_NGAP_ID"])
            ran_ue = safe_get_attr(layer, ["RAN_UE_NGAP_ID", "rAN_UE_NGAP_ID"])

            if amf_ue or ran_ue:
                return f"ngap|{amf_ue}|{ran_ue}"

        elif protocol == "f1ap":
            cu_ue = safe_get_attr(layer, ["GNB_CU_UE_F1AP_ID", "gNB_CU_UE_F1AP_ID"])
            du_ue = safe_get_attr(layer, ["GNB_DU_UE_F1AP_ID", "gNB_DU_UE_F1AP_ID"])

            if cu_ue or du_ue:
                return f"f1ap|{cu_ue}|{du_ue}"

        elif protocol == "e1ap":
            cp_ue = safe_get_attr(layer, ["GNB_CU_CP_UE_E1AP_ID", "gNB_CU_CP_UE_E1AP_ID"])
            up_ue = safe_get_attr(layer, ["GNB_CU_UP_UE_E1AP_ID", "gNB_CU_UP_UE_E1AP_ID"])
            key = cp_ue or up_ue
            if key:
                return f"e1ap|{key}"

    except Exception:
        pass

    return None


pcap_file = input("Enter file name: ").strip()

if not pcap_file.endswith(".pcap"):
    pcap_file += ".pcap"

if not os.path.exists(pcap_file):
    print("PCAP file not found. Check the file name and path.")
    exit()

file_size = os.path.getsize(pcap_file)
print(f"File size: {format_size(file_size)}")

protocol = input("Enter protocol name: ").strip().lower()
message_filter = input("Enter message to find(press enter to display all): ").strip().lower()
log_limit_input = input("Enter log size limit [default 1GB]: ").strip()

final_filter = protocol

log_size_limit = parse_size(log_limit_input)

sctp_chunk_names = {
    "0": "DATA", "1": "INIT", "2": "INIT_ACK", "3": "SACK",
    "4": "HEARTBEAT", "5": "HEARTBEAT_ACK", "6": "ABORT",
    "7": "SHUTDOWN", "8": "SHUTDOWN_ACK", "9": "ERROR",
    "10": "COOKIE_ECHO", "11": "COOKIE_ACK", "12": "ECNE",
    "13": "CWR", "14": "SHUTDOWN_COMPLETE"
}

ngap_procedure_names = {
    "0": "AMFConfigurationUpdate", "1": "AMFStatusIndication",
    "4": "DownlinkNASTransport", "14": "InitialContextSetup",
    "15": "InitialUEMessage", "21": "NGSetup",
    "24": "Paging", "25": "PathSwitchRequest", "28": "PDUSessionResourceRelease",
    "29": "PDUSessionResourceSetup", "41": "UEContextRelease",
    "44": "UERadioCapabilityInfoIndication",
    "46": "UplinkNASTransport",
}

e1ap_procedure_names = {
    "4": "GNB-CU-CP-E1Setup",
    "5": "E1Setup", "7": "UEContextSetup",
    "8": "BearerContextSetup", "9": "BearerContextModification",
    "10": "UEContextModificationRequired", "11": "BearerContextRelease",
    "12": "BearerContextModification", "13": "BearerContextModificationRequired",
    "14": "BearerContextRelease", "15": "BearerContextReleaseRequest",
}

f1ap_procedure_names = {
    "1": "F1Setup", "5": "UEContextSetup",
    "6": "UEContextRelease", "7": "UEContextModification",
    "8": "UEContextModificationRequired", "10": "Paging",
    "11": "InitialULRRCMessageTransfer", "12": "DLRRCMessageTransfer",
    "13": "ULRRCMessageTransfer", "18": "Paging",
}

xnap_procedure_names = {
    "17": "XnSetup",
    "0": "Handover",
    "1": "SNStatusTransfer",
    "6": "UEContextRelease",
}

icmpv6_type_names = {
    "133": "RouterSolicitation",
    "134": "RouterAdvertisement",
    "135": "NeighborSolicitation",
    "136": "NeighborAdvertisement",
    "143": "MulticastListenerReportMessageV2",
}

icmp_type_names = {
    "0": "EchoReply",
    "3": "DestinationUnreachable",
    "4": "SourceQuench",
    "5": "Redirect",
    "8": "EchoRequest",
    "11": "TimeExceeded",
    "12": "ParameterProblem",
    "13": "TimestampRequest",
    "14": "TimestampReply",
}

gtp_message_names = {
    "0x01": "EchoRequest",
    "0x02": "EchoResponse",
    "0x10": "CreatePDPContextRequest",
    "0x11": "CreatePDPContextResponse",
    "0x12": "UpdatePDPContextRequest",
    "0x13": "UpdatePDPContextResponse",
    "0x14": "DeletePDPContextRequest",
    "0x15": "DeletePDPContextResponse",
    "0xfe": "EndMarker",
    "0xff": "T-PDU",
}

pfcp_message_names = {
    "1":  "HeartbeatRequest",
    "2":  "HeartbeatResponse",
    "5":  "AssociationSetupRequest",
    "6":  "AssociationSetupResponse",
    "12": "NodeReportRequest",
    "13": "NodeReportResponse",
    "50": "SessionEstablishmentRequest",
    "51": "SessionEstablishmentResponse",
    "54": "SessionDeletionRequest",
    "55": "SessionDeletionResponse",
}

def get_message(pkt, protocol):
    try:
        if protocol == "sctp" and hasattr(pkt, "sctp") and hasattr(pkt.sctp, "chunk_type"):
            num = str(pkt.sctp.chunk_type)
            return sctp_chunk_names.get(num, f"CHUNK_{num}")

        elif protocol == "sip" and hasattr(pkt, "sip") and hasattr(pkt.sip, "Method"):
            return str(pkt.sip.Method)

        elif protocol == "pfcp" and hasattr(pkt, "pfcp") and hasattr(pkt.pfcp, "msg_type"):
            num = str(pkt.pfcp.msg_type)
            return pfcp_message_names.get(num, f"PFCP_MSG_{num}")

        elif protocol == "ngap" and hasattr(pkt, "ngap") and hasattr(pkt.ngap, "procedurecode"):
            num = str(pkt.ngap.procedurecode)
            fields = pkt.ngap.field_names
            # find the specific message element field
            for field in fields:
                if field.endswith("_element") and field not in (
                "protocolie_field_element", "ie_field_value_element",
                "initiatingmessage_element", "successfuloutcome_element",
                "unsuccessfuloutcome_element", "initiatingmessagevalue_element",
                "successfuloutcome_value_element"
                ):
                    return field.replace("_element", "")
            return ngap_procedure_names.get(num, f"NGAP_PROCEDURE_{num}")
            
        elif protocol == "f1ap" and hasattr(pkt, "f1ap") and hasattr(pkt.f1ap, "procedureCode"):
            num = str(pkt.f1ap.procedureCode)
            fields = pkt.f1ap.field_names
            for field in fields:
                if field.endswith("_element") and field not in (
                "protocolie_field_element", "protocolie_field_value_element",
                "initiatingmessage_element", "successfuloutcome_element",
                "unsuccessfuloutcome_element", "initiatingmessage_value_element",
                "successfuloutcome_value_element", "initiatingmessagevalue_element"
        ):
                    return field.replace("_element", "")
            return f1ap_procedure_names.get(num, f"F1AP_PROCEDURE_{num}")

        elif protocol == "e1ap" and hasattr(pkt, "e1ap") and hasattr(pkt.e1ap, "procedureCode"):
            num = str(pkt.e1ap.procedureCode)
            fields = pkt.e1ap.field_names
            for field in fields:
                if field.endswith("_element") and field not in (
                "protocolie_field_element", "protocolie_field_value_element",
                "initiatingmessage_element", "successfuloutcome_element",
                "unsuccessfuloutcome_element", "initiatingmessage_value_element",
                "successfuloutcome_value_element", "initiatingmessagevalue_element"
                 ):
                    return field.replace("_element", "")
            return e1ap_procedure_names.get(num, f"E1AP_PROCEDURE_{num}")

        elif protocol == "xnap" and hasattr(pkt, "xnap") and hasattr(pkt.xnap, "procedureCode"):
            num = str(pkt.xnap.procedurecode)
            fields = pkt.xnap.field_names
            for field in fields:
                if field.endswith("_element") and field not in (
                "protocolie_field_element", "protocolie_field_value_element",
                "initiatingmessage_element", "successfuloutcome_element",
                "unsuccessfuloutcome_element", "initiatingmessage_value_element",
                "successfuloutcome_value_element"
              ):
                 return field.replace("_element", "")
            return xnap_procedure_names.get(num, f"XNAP_PROCEDURE_{num}")
        
        elif protocol == "icmpv6" and hasattr(pkt, "icmpv6") and hasattr(pkt.icmpv6, "type"):
            num = str(pkt.icmpv6.type)
            return icmpv6_type_names.get(num, f"ICMPV6_TYPE_{num}")
        
        elif protocol == "icmp" and hasattr(pkt, "icmp") and hasattr(pkt.icmp, "type"):
            num = str(pkt.icmp.type)
            return icmp_type_names.get(num, f"ICMP_TYPE_{num}")
            # print(f"DEBUG icmp type: {pkt.icmp.type}")
            # return "UNKNOWN"

        elif protocol == "e2ap" and hasattr(pkt, "e2ap") and hasattr(pkt.e2ap, "procedureCode"):
            return str(pkt.e2ap.procedureCode)

        elif protocol == "gtp" and hasattr(pkt, "gtp") and hasattr(pkt.gtp, "message"):
            num = str(pkt.gtp.message)
            return gtp_message_names.get(num, f"GTP_MSG_{num}")
            

    except Exception:
        pass

    return "UNKNOWN"

def get_request_response_role(msg):
    msg_lower = msg.lower()
    if msg_lower.endswith("request") or msg_lower.endswith("command"):
        return "request"
    elif msg_lower.endswith("response") or msg_lower.endswith("acknowledge") or msg_lower.endswith("complete") or msg_lower.endswith("reply"):
        return "response"
    elif msg_lower.endswith("failure"):
        return "failure"
    return None


def get_message_family(msg):
    msg_lower = msg.lower()

    special_map = {
        "xnsetuprequest": "xnsetup",
        "xnsetupresponse": "xnsetup",
        "xnsetupfailure": "xnsetup",
        "handoverrequest": "handoverpreparation",
        "handoverrequestacknowledge": "handoverpreparation",
        "handoverpreparationfailure": "handoverpreparation",
        "retrieveuecontextrequest": "retrieveuecontext",
        "retrieveuecontextresponse": "retrieveuecontext",
        "retrieveuecontextfailure": "retrieveuecontext",
        "uecontextrelease": "uecontextrelease",
        "uecontextreleasecomplete": "uecontextrelease",
        "uecontextreleasefailure": "uecontextrelease",
        "uecontextreleasecommand": "uecontextrelease",
    }

    if msg_lower in special_map:
        return special_map[msg_lower]

    suffixes = ["request", "response", "failure", "acknowledge", "complete", "reply", "command"]
    for suffix in suffixes:
        if msg_lower.endswith(suffix):
            return msg_lower[:-len(suffix)]
    return msg_lower

cap = None
message_count = 0
all_message_counts = Counter()
matched_packets = []
current_log_size = 0
log_limit_reached = False
request_response_tracker = defaultdict(lambda: {"request": 0, "response": 0, "failure": 0})
request_response_totals = Counter()


try:
    cap = pyshark.FileCapture(
        pcap_file,
        display_filter=final_filter,
        keep_packets=False
    )

    for pkt in cap:
        try:
            src = (
                 pkt.ip.src if hasattr(pkt, "ip") else
                 pkt.ipv6.src if hasattr(pkt, "ipv6") else "N/A"
            )
            dst = (
                 pkt.ip.dst if hasattr(pkt, "ip") else
                 pkt.ipv6.dst if hasattr(pkt, "ipv6") else "N/A"
            )

            time = (
                pkt.frame_info.time_relative
                if hasattr(pkt, "frame_info") and hasattr(pkt.frame_info, "time_relative")
                else "N/A"
            )

            length_raw = (
                pkt.length if hasattr(pkt, "length")
                else pkt.frame_info.len if hasattr(pkt, "frame_info") and hasattr(pkt.frame_info, "len")
                else "0"
            )

            try:
                length_int = int(length_raw)
            except Exception:
                length_int = 0

            msg = get_message(pkt, protocol)
            msg_role = get_request_response_role(msg)
            msg_family = get_message_family(msg)
            txn_key = get_transaction_key(pkt, protocol)
            
            if current_log_size + length_int > log_size_limit:
                log_limit_reached = True
                break

            if message_filter:
                if message_filter != msg.lower():
                    continue
                message_count += 1

            matched_packets.append({
                "time": time,
                "length": length_int,
                "msg": msg,
                "src": src,
                "dst": dst
            })
            current_log_size += length_int
            all_message_counts[msg] += 1

            if msg_role in {"request", "response", "failure"}:
                request_response_totals[msg_role] += 1
                if msg_role == "request":
                    pair_key = (msg_family, src, dst, txn_key)
                else:
                    pair_key = (msg_family, dst, src, txn_key)
                request_response_tracker[pair_key][msg_role] += 1

        except Exception:
            continue

    if matched_packets:
        print("\nMessages found:\n")
        for item in matched_packets:
            print(f"{item['time']} | {item['length']} bytes | {protocol.upper()} | {item['msg']}")
    else:
        print("\nNo matching packets found.")

    # group sizes by message type
    variable_length_messages = {
    "DATA", "SACK",
    "uplinknastransport", "downlinknastransport",
    "initialuemessage"
}
    
    sizes_by_msg = defaultdict(list)
    for item in matched_packets:
        if item["msg"] in variable_length_messages:
            continue
        sizes_by_msg[item["msg"]].append(item["length"])

    # determine the most common ("expected") size per message
    expected_size_per_msg = {}
    for msg, sizes in sizes_by_msg.items():
        expected_size_per_msg[msg] = Counter(sizes).most_common(1)[0][0]

    # now flag packets that deviate from the expected size
    print("\nSize anomalies:\n")
    anomaly_found = False
    for item in matched_packets:
        if item["msg"] in variable_length_messages:
            continue
        expected = expected_size_per_msg[item["msg"]]
        if item["length"] != expected:
            anomaly_found = True
            print(
                f"Warning: {item['msg']} at {item['time']} has size {item['length']} bytes, "
                f"expected {expected} bytes"
            )

    if not anomaly_found:
        print("No size anomalies detected.")

    print("\nRequest-response totals:\n")
    print(f"Total requests : {request_response_totals['request']}")
    print(f"Total responses: {request_response_totals['response']}")
    print(f"Total failures : {request_response_totals['failure']}")

    print("\nRequest-response anomalies:\n")
    rr_problem_found = False
    any_rr_seen = False

    for (msg_family, src, dst, txn_key), counts in request_response_tracker.items():
        any_rr_seen = True
        req = counts["request"]
        resp = counts["response"]
        fail = counts["failure"]
        returned = resp + fail

        if req != returned:
            rr_problem_found = True
            if txn_key:
                print(
                    f"Warning: {msg_family} | {src} -> {dst} | key={txn_key} | "
                    f"requests={req}, responses={resp}, failures={fail}"
                )
            else:
                print(
                    f"Warning: {msg_family} | {src} -> {dst} | "
                    f"requests={req}, responses={resp}, failures={fail}"
                )

    if not any_rr_seen:
        print("No request-response style messages detected for this protocol.")
    elif not rr_problem_found:
        print("No request-response anomalies detected.")

    if log_limit_reached:
        print(f"\nLog size limit reached at {format_size(current_log_size)}. Stopped collecting more packets.")

    show_ip = input("\nDo you want to display source and destination also? (yes/no): ").strip().lower()

    if show_ip in ("yes", "y"):
        if matched_packets:
            print("\nMessages with source and destination:\n")
            for item in matched_packets:
                print(
                    f"{item['time']} | {item['length']} bytes | {protocol.upper()} | "
                    f"{item['msg']} | {item['src']} -> {item['dst']}"
                )
        else:
            print("No packets to display with source and destination.")

    if message_filter:
        print(f"\nTotal count of '{message_filter}': {message_count}")
    else:
        print("\nAll message counts:")
        for name, count in all_message_counts.items():
            print(f"{name}: {count}")


except FileNotFoundError:
    print("PCAP file not found. Check the file name and path.")

except TSharkCrashException:
    print("TShark crashed, likely invalid display filter or protocol")

finally:
    try:
        if cap is not None:
            cap.close()
    except TSharkCrashException:
        pass
    except Exception:
        pass