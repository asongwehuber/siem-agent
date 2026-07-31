from normalization.parsers.factory import get_parser

def normalize_log(log):

    parser = get_parser(
        log["generator_id"]
    )

    normalized = parser.normalize(log)

    # Preserve metadata from the original log
    normalized["generator_id"] = log["generator_id"]
    normalized["event_id"] = log["event_id"]
    normalized["timestamp"] = log["timestamp"]
    normalized["signature"] = log["signature"]

    validation = parser.validate(normalized)

    normalized["validation"] = validation

    return normalized