from enum import Enum

# Enum to represent the possible actions to be taken when a detection
class Action(Enum):

    ALERT = 1 # raise alert
    PASS = 2 # ignore

    # Return action corresponding to the string
    def action(istr):
        
        action = istr.lower().strip() # Normalize the input string
        
        try: 
            if(action == "alert"):
                return Action.ALERT
            if(action == "pass"):
                return Action.PASS

        except ValueError as e:
            print("Invalid rule for incorrect action : {e}")