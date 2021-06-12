from hashlib import sha256

def register(username, password):
    h = str(sha256(password.encode('utf-8')).digest())
    print(h)
    to_save = username + ';' + h + '\n'
    with open("./users.txt", "a") as myfile:
        myfile.write(to_save)

def login(username, password):
    file1 = open('./users.txt', 'r')
    for l in file1.readlines():
        r = l.split(';')
        if(r[0] == username):
            h = str(sha256(password.encode('utf-8')).digest())
            if(h == r[1].strip('\n')):
                print('login successful')
                return True
            else:
                print('wrong password')
                return False
    print('No such username')
    return False


#register('boas', 'amigo')
#register('joao', 'camiao')
#register('cris', 'cr7')
#register('eder', 'frança')
login('cris', 'cr7')
login('joao', 'pass')
login('manel', 'pass')