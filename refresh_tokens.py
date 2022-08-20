import requests
from datetime import datetime

with open("tokens.txt","r+") as tk:
    lines = tk.readlines()
    refresh_token_cn = lines[2][:-1]
    refresh_token_cv = lines[7][:-1]
    refresh_token_cf = lines[12][:-1]
    tk.truncate(0)
    tk.seek(0)
    response_json_cn = (requests.post("https://api.mercadolibre.com/oauth/token", data={"grant_type": "refresh_token", "client_id": "5502809460644628","client_secret": "RpF79P6wP0VtVUw7wi4Tb0aiyzPJuENN","refresh_token": refresh_token_cn,"redirect_uri":"https://socialpijamas.mx/"}, headers={"accept":"application/json","content-type": "application/x-www-form-urlencoded"})).json() #update access token
    response_json_cv = (requests.post("https://api.mercadolibre.com/oauth/token", data={"grant_type": "refresh_token", "client_id": "5502809460644628","client_secret": "RpF79P6wP0VtVUw7wi4Tb0aiyzPJuENN","refresh_token": refresh_token_cv,"redirect_uri":"https://socialpijamas.mx/"}, headers={"accept":"application/json","content-type": "application/x-www-form-urlencoded"})).json() #update access token
    response_json_cf = (requests.post("https://api.mercadolibre.com/oauth/token", data={"grant_type": "refresh_token", "client_id": "5502809460644628","client_secret": "RpF79P6wP0VtVUw7wi4Tb0aiyzPJuENN","refresh_token": refresh_token_cf,"redirect_uri":"https://socialpijamas.mx/"}, headers={"accept":"application/json","content-type": "application/x-www-form-urlencoded"})).json() #update access token
    tk.writelines([
        "Cuenta Nueva\n", #0
        "Refresh Token:\n", #1
        response_json_cn["refresh_token"], #2
        "\nAccess Token:\n", #3
        response_json_cn["access_token"], #4
        "\nCuenta Vieja\n", #5
        "Refresh Token:\n", #6
        response_json_cv["refresh_token"], #7
        "\nAccess Token:\n", #8
        response_json_cv["access_token"], #9
        "\nCuenta Franquicia\n", #10
        "Refresh Token:\n", #11
        response_json_cf["refresh_token"], #12
        "\nAccess Token:\n", #13
        response_json_cf["access_token"], #14
        "\nUltima vez actualizado:\n",str(datetime.today())]) #15
    print("Successfully resfreshed at",str(datetime.today()))
