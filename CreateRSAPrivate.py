#! /usr/bin/python
# encoding: utf-8
'''
rsahack.CreateRSAPrivate 

rsahack.CreateRSAPrivate
    Generate RSA Private Key from p, q and r

@author:     Cristian Amicelli Rivero
        
@copyright:  2013
        
@license:    license

@contact:    info@cristianamicelli.com.ar
@deffield    updated: 1 Beta
'''

from Crypto.Util import asn1
import os

__all__ = []
__version__ = 0.7
__date__ = '2013-06-02'
__updated__ = '2013-11-01'


def extended_gcd(a, b):
    x, last_x = 0, 1
    y, last_y = 1, 0
 
    while b:
        quotient = a // b
        a, b = b, a % b
        x, last_x = last_x - quotient*x, x
        y, last_y = last_y - quotient*y, y
    return (last_x, a)

def inverse_mod(a, m):
    x,  gcd = extended_gcd(a, m)
    if gcd == 1:
        return (x + m) % m
    else:
        return None   

def GenRSAPriv(p,q,e):
                    
    phi = (p - 1) * (q - 1)
    d = inverse_mod(e, phi)
    
    seq = asn1.DerSequence()
    seq[:] = [0,p*q,e,d,p,q,d%(p-1),d%(q-1),inverse_mod(q,p)]
    exported_key ="-----BEGIN RSA PRIVATE KEY-----\n%s-----END RSA PRIVATE KEY-----" % seq.encode().encode("base64")  
    rsa_priv= './almacen/privatekey.pem'
    if os.path.exists(rsa_priv):
        os.remove(rsa_priv)
        
    rsa_priv_key= open(rsa_priv,'w')
    rsa_priv_key.write(exported_key)
    rsa_priv_key.close()    
    return rsa_priv, exported_key
    
