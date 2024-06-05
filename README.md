# UNSW-TTP-Recorder
El objetivo de este repositorio es obtener un conjunto de datos con ataques actualizados siguiendo el estilo del dataset UNSW-NB15 y por otro lado, detectar las diferentes tácticas, técnicas y procedimientos definidos por MITRE ATT&CK.
## Primeros pasos y prerequisitos
Se necesitan tener instaladas previamente las siguientes librerias:
- Keras
- TensorFlow
- JupyterNotebook
- Python3
- Librerías de Python: Pandas, Numpy, Scikit-learn, Matplotlib, Pickle

Además se deben descargar del repositorio oficial del UNSW-NB15 https://research.unsw.edu.au/projects/unsw-nb15-dataset, los siguientes archivos y almacenarlos en _machinelearningbinario_ y _machinelearningmulticlase_ :
- NUSW-NB15_features.csv
- UNSW-NB15_1.csv
- UNSW-NB15_2.csv
- UNSW-NB15_3.csv
- UNSW-NB15_4.csv
## Instalación de Zeek
1. sudo apt-get install cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev
2. curl https://download.zeek.org/zeek-6.0.4.tar.gz --output zeek-6.0.4.tar.gz
3. tar -xzf zeek-6.0.4.tar.gz
4. ./configure
5. make && make install
## Instalación de Argus
1. git clone https://github.com/openargus/argus
2. cd argus
3. ./configure
4. make && make install
## Elaboración del conjunto de datos de entrenamiento con las 49 características según el estilo del UNSW-NB15
1. Descargar este repositorio GITHUB en el dispositivo con *git clone*
2. Descargar una captura de tráfico en formato PCAP disponible en el repositorio oficial del UNSW-NB15 https://research.unsw.edu.au/projects/unsw-nb15-dataset y copiarla en el repositorio *UNSW* (en este caso se ha descargado la captura *10.pcap* de la carpeta *pcaps 17-2-2015*)
3. cd UNSW
4. Ejecutar Zeek
   - zeek ./mi_policy.zeek -C -r 10.pcap
5. Ejecutar Argus
   - argus -J -r 10.pcap -w ./argus.argus
   - ra -n -u -r argus.argus -c ‘,’ -s saddr sport daddr dport proto state dur sbytes dbytes sttl dttl sloss dloss service sload dload spkts dpkts swin dwin stcpb dtcpb smeanz dmeanz sjit djit stime ltime sintpkt dintpkt tcprtt synack ackdat sum – M dsrs = +time, +flow,
+metric,+agr,+jitter > argus.csv
6. python3 combined.py

Como resultado se obtendrá el archivo _combined_data.csv_ que contiene el conjunto de datos con las 49 características
## Obtención modelo de clasificación binaria
1. cd machinelearningbinario
2. jupyter notebook
3. Ejecutar los ficheros en el siguiente orden:
    1. LimpiezaDataset.ipynb
    2. Preprocessing.ipynb
    3. MLmodels.ipynb
    4. Prediction.ipynb

El directorio _final-ipynb_ contendrá todos los archivos relavantes del proceso y los correspondientes modelos de aprendizaje automático
## Obtención modelo de clasificación multiclase
1. cd machinelearningmulticlase
2. jupyter notebook
3. Ejecutar los ficheros en el siguiente orden:
    1. LimpiezaDataset.ipynb
    2. Preprocessing.ipynb
    3. MLmodels.ipynb
    4. Prediction.ipynb

Al igual que en el caso binario, el directorio _final-ipynb_ contendrá todos los archivos relavantes del proceso y los correspondientes modelos de aprendizaje automático
## Ejecución de las predicciones de las etiquetas binarias y multiclaseobtención del conjunto final
1. cd UNSW
2. jupyter notebook
3. Ejecutar los archivos en el siguiente orden:
    1. PrediccionMulticlase.ipynb
    2. PrediccionBinaria.ipynb

Se obtendrá el fichero _datasetcompleto.csv_ que corresponde al cojunto de datos completo con las 49 características y las etiquetas binaria y multiclase
## Detección de las tácticas, técnicas y procedimiento de MITRE ATT&CK
Descargar una captura de tráfico que contenga alguna TTP y copiarla en el directorio *TTPS*, en este caso se ha descargado la captura correspondiente al _Unit 42 Wireshark Quiz, February 2023_ disponible en el sitio web https://www.malware-traffic-analysis.net
1. cd TTPS
2. Crear una nueva carpeta (en este caso se le ha llamado *bzar*) en el directorio reservado para paquetes en Zeek (por defecto es */usr/local/zeek/share/zeek/site/packages/bzar/*) y copiar los siguiente archivos:
    - \_\_load__.zeek
    - bzar_config_options.zeek
    - bzar_dce-rpc_consts.zeek
    - bzar_dce-rpc_detect.zeek
    - bzar_dce-rpc_report.zeek
    - bzar_files.zeek
    - bzar_smb1_detect.zeek
    - bzar_smb2_detect.zeek
    - bzar_smb_consts.zeek
    - bzar_smb_report.zeek
    - dpd.sig
    - main.zeek
3. zeek /usr/local/zeek/share/zeek/site/packages/bzar/\_\_load__.zeek ./mi_policy.zeek -C -r 2023- 02-Unit42-Wireshark-quiz.pcap
4. argus -J -r 2023-02-Unit42-Wireshark-quiz.pcap -w ./argus.argus
5. ra n -u -r argus.argus -c ‘,’ -s saddr sport daddr dport proto state dur sbytes dbytes sttl dttl
sloss dloss service sload dload spkts dpkts swin dwin stcpb dtcpb smeanz dmeanz sjit djit stime ltime sintpkt dintpkt tcprtt synack ackdat sum – M dsrs = +time, +flow, +metric,+agr,+jitter > argus.csv
6. python3 combined.py
7. python3 notice.py

Como resultado se generará el fichero _notice_data.csv_ que contiene las características de cada conexión y dos nuevas columnas indicando las tácticas y técnicas correspondientes.  