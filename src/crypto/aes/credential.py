class Credential:
    def __init__(self, website: str, username: str, password: str):
        self.website = website
        self.username = username
        self.password = password


    def to_dict(self):
        return {
            self.website : {
                "username" : self.username,
                "password" : self.password
            }
        }