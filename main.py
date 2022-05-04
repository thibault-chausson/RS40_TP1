# -*- coding: utf-8 -*-
"""
Created on Fri Apr 17 13:44:40 2020

@author: Mr ABBAS-TURKI
"""

import hashlib
import binascii
import math


def home_mod_expnoent(x, y, n):  # exponentiation modulaire (on prend x puissance y)
    ##Le code marche mais quand on l'utilise dans le programme du bas ce bug
    #(r1,r2)=(1,x)
    #while (y>0):
    #    if (y%2==1):
    #        r1=(r1*r2)%n
    #    r2=(r2**2)%n
    #    y=y//2
    return(pow(x,y,n))




def home_ext_euclide(a, b):  # algorithme d'euclide étendu pour la recherche de l'exposant on a r=au+bv
    (r,u,v,rp,up,vp)=(a,1,0,b,0,1)
    while rp!=0:
        q=r//rp
        (r, u, v, rp, up, vp) = (rp , up , vp , r-q*rp , u-q*up , v-q*vp)
    return (v)



def home_pgcd(a, b):  # recherche du pgcd
    if (b == 0):
        return a
    else:
        return home_pgcd(b, a % b)


def home_string_to_int(x):  # pour transformer un string en int
    z = 0
    for i in reversed(range(len(x))):
        z = int(ord(x[i])) * pow(2, (8 * i)) + z
    return (z)


def home_int_to_string(x):  # pour transformer un int en string
    txt = ''
    res1 = x
    while res1 > 0:
        res = res1 % (pow(2, 8))
        res1 = (res1 - res) // (pow(2, 8))
        txt = txt + chr(res)
    return txt


def mot10char(q,p):  # entrer le secret
    secret = input("donner un secret de log_2(n) caractères au maximum : ")
    while (len(secret) > math.log2(q*p)):
        secret = input("c'est beaucoup trop long, 10 caractères S.V.P : ")
    return (secret)



##Pour le reste chinois

def calculPreliminaire(xi, xj,d):
    n=xi*xj
    #phiq = (xi-1)*(xj-1)
    if (xi<xj):
        q=xi
        p=xj
    else:
        q=xj
        p=xi
    qPrime=home_ext_euclide(p,q)
    dq=d%(q-1)
    dp=d%(p-1)
    return(qPrime,dq,dp,q,p,n)

def CRT(xi,xj, d, c): #c correspond au message
    (qPrime, dq, dp, q, p,n)=calculPreliminaire(xi,xj, d)
    mq=home_mod_expnoent(c,dq,q)
    mp=home_mod_expnoent(c,dp,p)
    h=((mp-mq)*qPrime)%p
    m=(mq+h*q)%n
    return m




##On va sur bigprimes.org et on utilise 60 carractères pour sha256

# voici les éléments de la clé d'Alice

x1a = 873311000421951395668413761180963055862507620076542304172947  # p
x2a = 285552279012849749855169578136092776046272771929917292230809  # q

#x1a = 2010942103422233250095259520183  # p
#x2a = 3503815992030544427564583819137  # q


na = x1a * x2a  # n
phia = ((x1a - 1) * (x2a - 1)) // home_pgcd(x1a - 1, x2a - 1)


ea = 17  # exposant public
da = home_ext_euclide(phia, ea)  # exposant privé
# voici les éléments de la clé de bob


x1b = 609593912230569678098577269286226950711549466380196226468827  # p
x2b = 365194022714328554543797939423556399764784076098815492083787  # q


#x1b = 9434659759111223227678316435911  # p
#x2b = 8842546075387759637728590482297  # q


nb = x1b * x2b  # n
phib = ((x1b - 1) * (x2b - 1)) // home_pgcd(x1b - 1, x2b - 1)
eb = 23  # exposants public
db = home_ext_euclide(phib, eb)  # exposant privé

print("Vous êtes Bob, vous souhaitez envoyer un secret à Alice")
print("voici votre clé publique que tout le monde a le droit de consulter (de Bob)")
print("n =", nb)
print("exposant :", eb)
print("voici votre précieux secret")
print("d =", db)
print("*******************************************************************")
print("Voici aussi la clé publique d'Alice que tout le monde peut consulter")
print("n =", na)
print("exposent :", ea)
print("*******************************************************************")
print("il est temps de lui envoyer votre secret ")
print("*******************************************************************")
x = input("appuyer sur entrer")
secret = mot10char(x1a,x2b)
print("*******************************************************************")
print("voici la version en nombre décimal de ", secret, " : ")
num_sec = home_string_to_int(secret)
print(num_sec)
print("voici le message chiffré avec la clé publique d'Alice : ")
chif = home_mod_expnoent(num_sec, ea, na)
print(chif)
print("*******************************************************************")
print("On utilise la fonction de hashage sha256 pour obtenir le hash du message", secret)
Bhachis0 = hashlib.sha256(secret.encode(encoding='UTF-8', errors='strict')).digest()  # sha256 du message
print("voici le hash en nombre décimal ")
Bhachis1 = binascii.b2a_uu(Bhachis0)
Bhachis2 = Bhachis1.decode()  # en string
Bhachis3 = home_string_to_int(Bhachis2)
print(Bhachis3)
print("voici la signature avec la clé privée de Bob du hachis")
signe = home_mod_expnoent(Bhachis3, db, nb)
print(signe)

print("voici la signature avec la clé privée de Bob du hachis avec le CRT")
signe2 = CRT(x1b, x2b, db, Bhachis3)
print(signe2)

print("*******************************************************************")
print("Bob envoie \n \t 1-le message chiffré avec la clé public d'Alice \n", chif, "\n \t 2-et le hash signé \n", signe)
print("*******************************************************************")
x = input("appuyer sur entrer")
print("*******************************************************************")
print("Alice déchiffre le message chiffré \n", chif, "\nce qui donne ")
dechif = home_int_to_string(home_mod_expnoent(chif, da, na))
print(dechif)

print("Passons au déchiffrement par le CRT")
dechiffreCRT=CRT(x1a,x2a,da, chif)
print("Alice déchiffre son fameux message avec la clé de Bob, ce qui donne : ")
print(home_int_to_string(dechiffreCRT))

print("*******************************************************************")
print("Alice déchiffre la signature de Bob \n", signe, "\n ce qui donne  en décimal")
designe = home_mod_expnoent(signe, eb, nb)
print(designe)

print("Alice déchiffre la signature CRT de Bob \n", signe2, "\n ce qui donne  en décimal")
designe2 = home_mod_expnoent(signe2, eb, nb)
print(designe2)

print("Alice vérifie si elle obtient la même chose avec le hash de ", dechif)
Ahachis0 = hashlib.sha256(dechif.encode(encoding='UTF-8', errors='strict')).digest()
Ahachis1 = binascii.b2a_uu(Ahachis0)
Ahachis2 = Ahachis1.decode()
Ahachis3 = home_string_to_int(Ahachis2)
print(Ahachis3)
print("La différence =", Ahachis3 - designe)
if (Ahachis3 - designe == 0):
    print("Alice : Bob m'a envoyé : ", dechif)
else:
    print("oups")


print("La différence pour le CRT =", Ahachis3 - designe2)
if (Ahachis3 - designe2 == 0):
    print("Alice : Bob m'a envoyé : ", dechif)
else:
    print("oups")





##k minimum 32 octets
