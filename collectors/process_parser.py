import xml.etree.ElementTree as ET

def parse_event_xml(xml_data) :

    root = ET.fromstring(xml_data)

    parsed_event = {}

    namespace = {"ns" : "http://schemas.microsoft.com/win/2004/08/events/event"}

    for data in root.findall(".//ns:Data",namespace) :

        name = data.attrib.get("Name")

        value = data.text

        parsed_event[name] = value 

    return parsed_event