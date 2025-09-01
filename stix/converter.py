import json

def extract_objects_from_stix(input_file, output_file):
    # Leer archivo JSON
    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    result = []

    # Iterar sobre los objetos
    for obj in data.get("objects", []):
        if obj["type"] == "attack-pattern":
            # Buscar la táctica desde kill_chain_phases (si existe)
            tactic_name = None
            if "kill_chain_phases" in obj and obj["kill_chain_phases"]:
                tactic_name = obj["kill_chain_phases"][0]["phase_name"]

            # Construir objeto simplificado
            simplified = {
                "type": "technique",
                "external_id": obj.get("x_mitre_id") or get_external_id(obj),
                "name": obj.get("name"),
                "description": obj.get("description"),
                "x_mitre_tactic_type": tactic_name
            }
            result.append(simplified)

        elif obj["type"] in ["x-mitre-tactic", "tactic"]:
            # Si ya viene como táctica (por ejemplo ST0001 / ST0002)
            simplified = {
                "type": "tactic",
                "external_id": get_external_id(obj),
                "name": obj.get("name"),
                "description": obj.get("description"),
                "techniques": []  # luego se llenará
            }
            result.append(simplified)

    # Guardar a archivo
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4, ensure_ascii=False)

    print(f"Archivo generado: {output_file}")


def get_external_id(obj):
    """
    Busca external_id en external_references si no está en x_mitre_id
    """
    if "external_references" in obj:
        for ref in obj["external_references"]:
            if "external_id" in ref:
                return ref["external_id"]
    return None


# Ejemplo de uso
if __name__ == "__main__":
    extract_objects_from_stix("sparta.json", "output_converter.json")
