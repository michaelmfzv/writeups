#!/bin/bash

# Creación de la carpeta
mkdir $1

mkdir $1/Images

# Creación de la documentación
cp example.md $1/Readme.md
sed -i "s/{machineName}/$1/g" $1/Readme.md
sed -i "s/{machineIP}/$2/g" $1/Readme.md

echo "Máquina $1 - $2 creada con exito"
