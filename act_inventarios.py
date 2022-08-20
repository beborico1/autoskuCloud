import ssl
import smtplib
import shopify
import requests
import time
from datetime import datetime, timedelta
from email.message import EmailMessage

output = ""

usuarios_ml = {
            "Cuenta Vieja": {
                "user_id":"658055303",
                "at_line":9,
                "inventarios": ["Hermosillo"]
            },
            "Cuenta Nueva": {
                "user_id":"803281630",
                "at_line":4,
                "inventarios": ["Hermosillo"]
            },
            "Cuenta Franquicia": { 
                "user_id": "828938197",
                "at_line":14,
                "inventarios": ["Hermosillo","Guadalajara","Puebla","CDMX"]
            }
        }

def leerAdminbox():
    global output
    urls = {
    "Hermosillo":"https://www.adminbox.com.mx/v6/webservice/v1/existencias.php?token=13060a3e2be8bf3b43f1b67011ecfa5d",
    "Guadalajara":"https://www.adminbox.com.mx/v6/webservice/v1/existencias.php?token=13060a3e2be8bf3b43f1b67011ecfa5d&almacen=6291621ed0e99d5042056166299e3d1b",
    "Puebla":"https://www.adminbox.com.mx/v6/webservice/v1/existencias.php?token=13060a3e2be8bf3b43f1b67011ecfa5d&almacen=54efa55abf6150433001d72cfbfbdf7f",
    "CDMX":"https://www.adminbox.com.mx/v6/webservice/v1/existencias.php?token=13060a3e2be8bf3b43f1b67011ecfa5d&almacen=93bbf777111dc399bb0a4a70c89a9fe1",
    }
    inventarios = {
    "Hermosillo":{},
    "Guadalajara":{},
    "Puebla":{},
    "CDMX":{}
    }
    for almacen, url in urls.items():
        request_json = safeGet(url,"data")
        productos = request_json["data"]
        for producto in productos:
            sku = producto["codigo"]
            try:
                cantidad = int(producto["existencia"])
            except:
                cantidad = 0
            inventarios[almacen][sku] = cantidad
    output = output + "Se leyeron %s inventarios de AdminBox\n" % str(len(urls))
    return inventarios

def combinarInventarios(inventarios): #Recibe una lista con los diccionarios de inventario
    inventario_mix = {}
    for inventario in inventarios:
        for sku, qty in inventario.items():
            inventario_mix.setdefault(sku, 0)
            inventario_mix[sku] += qty
    return inventario_mix

def actualizarInventarios(inventarios):
    global output
    for cuenta, info in usuarios_ml.items():
        print("Actualizando Mercado Libre %s..." % cuenta)
        output = output + ("Mercado Libre %s\n" % cuenta)
        headers_authorized = headers_authorizedML(info["at_line"])
        all_ids = obtenerProductosML(info["user_id"],headers_authorized)
        inventario = combinarInventarios(list({ inventario: inventarios[inventario] for inventario in info["inventarios"] }.values()))
        actualizarCantidadesML(all_ids,inventario,headers_authorized)
    actualizarShopify(inventarios,inicializarShopifyAPI())
    hoy = datetime.today() - timedelta(hours = 7)
    print(hoy)
    output = output + str("%s\n" % hoy)

def headers_authorizedML(at_line):
    with open("tokens.txt","r") as tk:
        access_token = tk.readlines()[at_line][:-1]
        return {"accept":"application/json","content-type": "application/x-www-form-urlencoded","Authorization":"Bearer %s" % access_token}

def obtenerProductosML(user_id,headers_authorized):
    request_url = "https://api.mercadolibre.com/users/%s/items/search?search_type=scan" % (user_id)
    response_json = safeGetWHeaders(request_url,headers_authorized,"results")
    all_ids = []
    while True:
        batch_ids = response_json["results"]
        if len(batch_ids) == 0:
            break
        all_ids = all_ids + batch_ids
        scroll_id = response_json["scroll_id"]
        request_url = "https://api.mercadolibre.com/users/%s/items/search?search_type=scan&scroll_id=%s" % (user_id,scroll_id)
        response_json = safeGetWHeaders(request_url,headers_authorized,"results")
    return all_ids

def actualizarCantidadesML(item_ids,inventario,headers_authorized):
    global output
    updated_products = 0
    for item_id in item_ids:
        response_json = safeGetWHeaders("https://api.mercadolibre.com/items/%s?include_attributes=all" % item_id, headers_authorized,"variations") #Publicamos el json en la url correspondiente
        variations = response_json["variations"]
        if variations:
            variations_qty = {}
            for variation in variations:
                attributes = variation["attributes"]
                variations_qty[variation["id"]] = 0
                for attribute in attributes:
                    if attribute["name"] == "SKU":
                        sku = attribute["value_name"]
                        if sku in inventario:
                            variations_qty[variation["id"]] = inventario[sku]
                todo = { "variations": []}
            for variation, qty in variations_qty.items():
                todo["variations"].append({ "id": variation, "available_quantity": qty })
            safePut("https://api.mercadolibre.com/items/%s" % item_id, headers = headers_authorized, json=todo) #Publicamos el json en la url correspondiente
            updated_products += 1
        else:
            attributes = response_json["attributes"]
            for attribute in attributes:
                if attribute["name"] == "SKU":
                    sku = attribute["value_name"]
                    if sku in inventario:
                        qty = inventario[sku]
                        todo = {"available_quantity": qty}
                        safePut("https://api.mercadolibre.com/items/%s" % item_id, headers = headers_authorized, json=todo) #Publicamos el json en la url correspondiente
                        updated_products += 1
    print(updated_products,"productos se actualizaron")
    output = output + str("%s productos se actualizaron\n" % updated_products)

def inicializarShopifyAPI(): #Configuramos el API de Shopifyl
    API_KEY = "d988992fe245682911e1806c6ea8403e" #La llave del API de shopify
    PASSWORD = "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" #La contrasena del API de shopify
    shop_url = "https://%s:%s@socialpijamas.myshopify.com/admin" % (API_KEY, PASSWORD) #LA URL DEL ADMIN DE LA API
    shopify.ShopifyResource.clear_session #Limpiamos la sesion
    shopify.ShopifyResource.set_site(shop_url) #Configuramos
    shop_api_url = shop_url + "/api/2022-04/" #LA URL DEL API
    return shop_api_url

def actualizarShopify(inventarios,shop_api_url):
    global output
    print("Actualizando Shopify...")
    output = output + "Shopify\n"
    updated_products = 0
    locationIDs = {"CDMX":65831829695,"Hermosillo":49600397474,"Puebla":62398398655,"Guadalajara":62398529727} #Los codigos de las sucrulas en shopify
    last_id = 0 #ultimo id de producto que usaremos para paginar los productos leido
    while True: #Loop repetido por pagina de datos leida en productos
        response_json = safeGet("%sproducts.json?since_id=%s" % (shop_api_url,last_id),"products")
        products = response_json["products"]
        batchIDs = [] #Limpiamos el arreglo de id de productos leidos en la tanda
        for product in products: #por cada producto leido
            batchIDs.append(product["id"]) #Agregamos su id a la lista
            for variant in product["variants"]: #Por cada variante del producto
                for location in locationIDs: #Por sucursal
                    sku = (str([variant["sku"]][0]).split(".", 1))[0] #Limpiamos el sku
                    if sku in inventarios[location]: #Si existe el sku en el inventario de esa sucrusal
                        qty = inventarios[location][sku]
                        #print("Posting product with sku",sku,"qty",qty,"in location",location)
                        todo = { "location_id": locationIDs[location], "inventory_item_id": variant["inventory_item_id"], "available": qty }
                        safePost("%sinventory_levels/set.json" % shop_api_url, json=todo) #Publicamos el json en la url correspondiente
            updated_products += 1
            if updated_products > 10:
                break
        if len(batchIDs) == 0:
            break
        else:
            last_id = batchIDs[-1]
    print(updated_products,"productos se actualizaron")
    output = output + str("%s productos se actualizaron\n" % updated_products)

def sendemail(content):
    email_sender = "autoskusp@gmail.com"
    email_password = "qblo shtb sfmt erau"
    email_receiver = "beborico16@gmail.com,socialpijamas2@gmail.com"

    subject = "Actualizacion de Inventarios"

    em = EmailMessage()

    em["From"] = email_sender
    em["To"] = email_receiver
    em["Subject"] = subject
    em.set_content(content)

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL("smtp.gmail.com",465,context=context) as smtp:
        smtp.login(email_sender,email_password)
        smtp.sendmail(email_sender,email_receiver,em.as_string())

def safeMain():
    try:
        actualizarInventarios(leerAdminbox())
        sendemail(output)
    except Exception as e:
        try:
            sendemail("Hubo un error actualizando los inventarios\n%s" % e)
        except Exception as e2:
            print(e2)

def main():
    actualizarInventarios(leerAdminbox())

def safeGet(url,expectedKey):
    try:
        rj = requests.get(url).json()
        rj[expectedKey]
    except:
        time.sleep(1)
        rj = requests.get(url).json()
    return rj

def safeGetWHeaders(url,headers,expectedKey):
    try:
        rj = requests.get(url,headers=headers).json()
        rj[expectedKey]
    except:
        time.sleep(1)
        rj = requests.get(url,headers=headers).json()
    return rj

def safePost(url,json):
    try:
        requests.post(url,json=json)
    except:
        time.sleep(1)
        requests.post(url,json=json)

def safePut(url,headers,json):
    try:
        requests.put(url)
    except:
        time.sleep(1)
        requests.put(url)

safeMain()
