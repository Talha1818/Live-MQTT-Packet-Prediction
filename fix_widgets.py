import nbformat

nb_file = "MQTT_Blueprint_for_an_AI_Powered_Network_Monitoring_Agent_15Sep2025.ipynb"

# Load notebook
nb = nbformat.read(nb_file, as_version=4)

# Fix widgets metadata
if "widgets" in nb["metadata"]:
    widget_data = nb["metadata"]["widgets"].get("application/vnd.jupyter.widget-state+json", {})
    
    # If 'state' key is missing, wrap everything into 'state'
    if "state" not in widget_data:
        nb["metadata"]["widgets"]["application/vnd.jupyter.widget-state+json"] = {
            "version_major": 2,
            "version_minor": 0,
            "state": widget_data
        }

# Save fixed notebook
nbformat.write(nb, nb_file)
print(f"✅ Fixed {nb_file}")
