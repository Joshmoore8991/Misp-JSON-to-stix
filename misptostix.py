import json
import uuid
import logging
from typing import Dict, List, Any, Optional

import stix2
from stix2.base import _STIXBase

class MISPToSTIXConverter:
    def __init__(self, input_file: str, output_file: str):
        """
        Initialize the converter with input and output file paths.
        
        Args:
            input_file (str): Path to the input MISP JSON file
            output_file (str): Path to save the output STIX JSON file
        """
        self.input_file = input_file
        self.output_file = output_file
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO, 
            format='%(asctime)s - %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        self.logger = logging.getLogger(__name__)

    def load_misp_data(self) -> Dict[str, Any]:
        """
        Load MISP JSON data from the input file.
        
        Returns:
            Dict containing MISP data
        
        Raises:
            ValueError if file is invalid or cannot be loaded
        """
        try:
            with open(self.input_file, "r", encoding="utf-8") as file:
                misp_data = json.load(file)
            
            # Validate MISP data structure
            if not isinstance(misp_data, dict) or "values" not in misp_data:
                raise ValueError("Invalid MISP JSON format: Missing 'values' key")
            
            return misp_data
        except json.JSONDecodeError as e:
            self.logger.error(f"JSON Decode Error: {e}")
            raise
        except IOError as e:
            self.logger.error(f"File Read Error: {e}")
            raise

    def _sanitize_list(self, value: Any) -> List[str]:
        """
        Ensure a value is converted to a list of strings.
        
        Args:
            value: Input value to convert
        
        Returns:
            List of strings
        """
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return list(value)

    def create_threat_actor(self, item: Dict[str, Any]) -> Optional[stix2.ThreatActor]:
        """
        Create a STIX Threat Actor from a MISP item.
        
        Args:
            item (Dict): MISP threat actor item
        
        Returns:
            STIX Threat Actor object or None if creation fails
        """
        try:
            # Validate required fields
            if not all(key in item for key in ["uuid", "value"]):
                self.logger.warning(f"Skipping invalid item: {item}")
                return None

            actor_id = f"threat-actor--{item['uuid']}"
            
            # Extract metadata with fallback defaults
            meta = item.get("meta", {})
            
            # Sanitize list fields
            synonyms = self._sanitize_list(meta.get("synonyms"))
            refs = self._sanitize_list(meta.get("refs"))

            # Prepare labels
            labels = []
            if meta.get("country"):
                labels.append(f"Country: {meta['country']}")
            if meta.get("targeted-sector"):
                labels.append(f"Targeted Sector: {meta['targeted-sector']}")

            # Create external references
            external_references = [
                {"source_name": "MISP", "url": ref} 
                for ref in refs if isinstance(ref, str)
            ]

            # Create STIX Threat Actor
            threat_actor = stix2.ThreatActor(
                id=actor_id,
                name=item["value"],
                description=item.get("description", "No description available."),
                aliases=synonyms,
                labels=labels,
                external_references=external_references,
                confidence=int(meta.get("attribution-confidence", 50))
            )
            
            self.logger.info(f"Created Threat Actor: {item['value']}")
            return threat_actor

        except Exception as e:
            self.logger.error(f"Error creating Threat Actor {item.get('value', 'Unknown')}: {e}")
            return None

    def create_relationships(self, 
                              source_actor_id: str, 
                              related_items: List[Dict[str, Any]]
    ) -> List[stix2.Relationship]:
        """
        Create relationships for a given threat actor.
        
        Args:
            source_actor_id (str): ID of the source threat actor
            related_items (List): List of related items
        
        Returns:
            List of STIX Relationship objects
        """
        relationships = []
        
        for relation in related_items:
            try:
                if not all(key in relation for key in ["dest-uuid", "type"]):
                    self.logger.warning(f"Skipping invalid relationship: {relation}")
                    continue

                relationship = stix2.Relationship(
                    id=f"relationship--{uuid.uuid4()}",
                    relationship_type="related-to",
                    source_ref=source_actor_id,
                    target_ref=f"threat-actor--{relation['dest-uuid']}",
                    description=f"Relationship type: {relation['type']}",
                    confidence=80
                )
                
                relationships.append(relationship)
                self.logger.info(f"Created Relationship: {relationship}")
            
            except Exception as e:
                self.logger.error(f"Error creating relationship: {e}")
        
        return relationships

    def convert(self) -> None:
        """
        Main conversion method to transform MISP data to STIX.
        Handles the entire conversion process.
        """
        try:
            # Load MISP data
            misp_data = self.load_misp_data()
            
            # Initialize STIX objects list
            stix_objects: List[_STIXBase] = []

            # Process each MISP item
            for item in misp_data.get("values", []):
                # Create Threat Actor
                threat_actor = self.create_threat_actor(item)
                if threat_actor:
                    stix_objects.append(threat_actor)

                    # Create Relationships
                    if item.get("related"):
                        relationships = self.create_relationships(
                            threat_actor.id, 
                            item["related"]
                        )
                        stix_objects.extend(relationships)

            # Create STIX Bundle
            if not stix_objects:
                raise ValueError("No valid STIX objects created")

            # CHANGE: Manual serialization to avoid complex library serialization
            stix_bundle_data = {
                "type": "bundle",
                "id": f"bundle--{uuid.uuid4()}",
                "spec_version": "2.0",
                "objects": [json.loads(obj.serialize()) for obj in stix_objects]
            }

            # Save serialized data
            with open(self.output_file, "w", encoding="utf-8") as file:
                json.dump(stix_bundle_data, file, indent=4)

            self.logger.info(f"✅ STIX 2.0 JSON saved as {self.output_file}")

        except Exception as e:
            self.logger.error(f"Conversion failed: {e}")
            raise

def main():
    """
    Main execution function
    """
    converter = MISPToSTIXConverter(
        input_file="misp_data.json", 
        output_file="stix_output_2_0.json"
    )
    converter.convert()

if __name__ == "__main__":
    main()
