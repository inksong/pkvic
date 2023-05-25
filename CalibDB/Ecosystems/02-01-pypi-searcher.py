import xmlrpc.client
from tqdm import *
import pprint
import linecache

def step1():
    client = xmlrpc.client.ServerProxy('https://pypi.org/pypi')
    
    
    pkgs = client.list_packages()
    print(len(pkgs))
    
    
    # f = open('python_pypi_packages.list','a')
    # for onepkg in tqdm(pkgs):
    #     f.write(str(onepkg)+'\n')
    # f.close()

def step2():
    client = xmlrpc.client.ServerProxy('https://pypi.org/pypi')

    pkglist = []
    lines = linecache.getlines('python_pypi_packages.list')
    for oneline in lines:
        pkglist.append(str(oneline).strip())
    
    
    
    pairs = []
    
    for onepkg in tqdm(pkglist):
        curver = ""
        verlist = client.package_releases(onepkg)
        if len(verlist)>0:
            curver=verlist[0]
        
        pairs.append([onepkg, curver])
        
    f = open('python_pypi_packages_ver.list','a')
    for onepkgver in tqdm(pairs):
        curpkg = onepkgver[0]
        c_ver = onepkgver[1]
        f.write(str(curpkg)+' '+str(c_ver)+'\n')
    f.close()
step2()
