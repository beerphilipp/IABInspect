class DistinguishableScreenElement:

    def __init__(self, package, class_name, text, context_description, resource_id):
        self.package = package
        self.class_name = class_name
        self.text = text
        self.context_description = context_description
        self.resource_id = resource_id

    def __eq__(self, other: object) -> bool:
        if (other == None):
            return False
        
        if (type(other) != DistinguishableScreenElement):
            return False
        
        if (self.package != other.package):
            return False
        
        if (self.class_name != other.class_name):
            return False
        
        if (self.text != other.text):
            return False
        
        if (self.context_description != other.context_description):
            return False
        
        if (self.resource_id != other.resource_id):
            return False
        
        return True
    
    def to_dict(self):
        return {
            "package": self.package,
            "class": self.class_name,
            "text": self.text,
            "content-description": self.context_description,
            "resource-id": self.resource_id
        }