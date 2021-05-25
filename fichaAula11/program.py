import string
import requests
from bs4 import BeautifulSoup

whitelist = set(string.ascii_lowercase + string.ascii_uppercase + string.digits + '/' + ',')

def validate_chars(str):
    global whitelist
    for c in str:
        if c not in whitelist:
            print('ERRO: caracter invalido')
            return False
    return True 


def validateNIF(NIF: str) -> bool:
    if not (NIF.isdigit() and len(NIF) == 9):
        return False
    response = requests.get(f"https://www.nif.pt/?q={NIF}")
    response.raise_for_status()
    soup = BeautifulSoup(response.content, "html.parser")
    # Search for entity NIF
    entity = soup.find("span", class_="search-title")

    if entity is not None:
        return True
    message = soup.select('div[class*="alert-message"]')[0].text

    return True if "O NIF indicado é válido" in message else False


def checkLuhn(cardNo):
     
    nDigits = len(cardNo)
    nSum = 0
    isSecond = False
     
    for i in range(nDigits - 1, -1, -1):
        d = ord(cardNo[i]) - ord('0')
     
        if (isSecond == True):
            d = d * 2
  
        nSum += d // 10
        nSum += d % 10
  
        isSecond = not isSecond
     
    if (nSum % 10 == 0):
        return True
    else:
        return False





def inputs():
    valor = input('Valor (ex: 00,00): ')
    if(not validate_chars(valor)):
        return False

    data = input('Data de Nascimento (DD/MM/AAAA): ')
    if(not validate_chars(data)):
        return False

    nome = input('Nome (ex: José): ')
    if(not validate_chars(nome)):
        return False
    
    nif = input('NIF: ')
    if(not validate_chars(nif)):
        return False
    if(not validateNIF(NIF)):
        return False

    nic = input('NIC: ')
    if(not validate_chars(nic)):
        return False

    credit = input('Cartao credito (Numero): ')
    if(not validate_chars(credit) or credit == ''):
        return False
    if(not checkLuhn(credit)):
        return False

    validade = input('Cartao credito (Validade - MM/AA): ')
    if(not validate_chars(credit)):
        return False

    ccv = input('Cartao credito (CCV): ')
    if(not validate_chars(ccv)):
        return False
    return True

def main():
    print(inputs()==True)

main()