import json
from pathlib import Path


KNOWLEDGE_FILE = Path(
    "rag/knowledge/security_knowledge.json"
)


def load_knowledge():

    with open(
        KNOWLEDGE_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


def retrieve(attack_family):

    knowledge = load_knowledge()

    results = []

    for item in knowledge:

        if item["attack"].lower() == attack_family.lower():

            results.append(item)

    return results


def format_context(results):

    if not results:
        return "No relevant cybersecurity knowledge found."

    context = []

    for item in results:

        context.append(
            f"""
ATTACK TYPE:
{item['attack']}

DESCRIPTION:
{item['description']}

INDICATORS:
{', '.join(item['indicators'])}

INVESTIGATION STEPS:
{'; '.join(item['investigation'])}

MITIGATION:
{'; '.join(item['mitigation'])}
"""
        )

    return "\n".join(context)


if __name__ == "__main__":

    attack = "DoS"

    results = retrieve(
        attack
    )

    print(
        "\n========================================"
    )

    print(
        "       SENTINELAI RAG RETRIEVER"
    )

    print(
        "========================================"
    )

    print(
        f"\nQuery: {attack}"
    )

    print(
        f"Documents retrieved: {len(results)}"
    )

    print(
        "\nRetrieved Knowledge:"
    )

    print(
        format_context(results)
    )