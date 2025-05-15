

import hashlib


def getErrorResponse(type, message) :
        return {
            "status":"Error",
            "type": type,
            "message": message
        }

def getHashKey() :
    data = "type" + "params"
    return hashlib.sha1(data.encode()).hexdigest()

## Done to know if the data we got is in the required json format ##
def checkFormat(json_data):
    data_from_client = json_data.keys()
    data_format_from_client = ''.join(s for s in data_from_client)
    new_h = hashlib.sha1(data_format_from_client.encode()).hexdigest()
    old_h = getHashKey()
    return new_h == old_h

def commad_Params_check(cmd, params):
      if cmd == "register":
            return len(params) >=2
      return True

def getResponse(message) :
        return {
          "status":"OK",
          "type":"response",
          "message":message
     }


def getDefaultResposne():
     return {
          "status":"OK",
          "type":"response",
          "message":"data recived successfully"
     }

