import csv
import pandas as pd
import numpy as np

csv.field_size_limit(10000000)

argus_data = []
with open("./argus.csv", "r") as argus_file:
    reader = csv.DictReader(argus_file)
    for row in reader:
        argus_data.append(row)

argus_data = argus_data[1:-1]

for row in argus_data:
    row['StartTime'] = float(row['StartTime'])
    row['StartTime'] = int(row['StartTime'])
    row['LastTime'] = float(row['LastTime'])
    row['LastTime'] = int(row['LastTime'])
    del row['Sum']


zeek_data = []
with open("./my_log.log", "r") as zeek_file:
    for line in zeek_file:
        if line.startswith('#fields'):
            field_names = line.strip().split("\t")[1:]
            break

    for line in zeek_file:
        if line.startswith('#types'):
            field_types = line.strip().split("\t")[1:]
            break
    
    reader = csv.DictReader(zeek_file, delimiter="\t", fieldnames=field_names)
    for row in reader:
        if row['ts'] == '#close':
            break
        zeek_data.append(row)

for row in zeek_data:
    row['ts'] = float(row['ts'])
    row['ts'] = int(row['ts'])


ftp_data = []
with open("./ftp.log", "r") as ftp_file:
    for line in ftp_file:
        if line.startswith('#fields'):
            field_names = line.strip().split("\t")[1:]
            break

    for line in ftp_file:
        if line.startswith('#types'):
            field_types = line.strip().split("\t")[1:]
            break
    
    reader = csv.DictReader(ftp_file, delimiter="\t", fieldnames=field_names)
    for row in reader:
        if row['ts'] == '#close':
            break
        ftp_data.append(row)

http_data = []
with open("./http.log", "r") as http_file:
    for line in http_file:
        if line.startswith('#fields'):
            field_names = line.strip().split("\t")[1:]
            break

    for line in http_file:
        if line.startswith('#types'):
            field_types = line.strip().split("\t")[1:]
            break
    
    reader = csv.DictReader(http_file, delimiter="\t", fieldnames=field_names)
    for row in reader:
        if row['ts'] == '#close':
            break
        http_data.append(row)

for row in argus_data:
    for key, value in row.items():
        if value == '':
            row[key] = '0'

for argus_row in argus_data:
    
    argus_row['service'] = '-'
    argus_row['trans_depth'] = 0
    argus_row['res_bdy_len'] = 0
    argus_row['is_sm_ips_ports'] = 0
    argus_row['ct_state_ttl'] = 0
    argus_row['ct_flw_http_mthd'] = 0
    argus_row['is_ftp_login'] = 0
    argus_row['ct_ftp_cmd'] = 0

    for zeek_row in zeek_data:
        if(argus_row['SrcAddr'] == zeek_row['srcip'] and 
           argus_row['Sport'] == zeek_row['sport'] and
           argus_row['DstAddr'] == zeek_row['dstip'] and
           argus_row['Dport'] == zeek_row['dsport'] and
           argus_row['StartTime'] == zeek_row['ts']):
           
           argus_row['SrcAddr'] = zeek_row['srcip']
           argus_row['Sport'] = zeek_row['sport']
           argus_row['DstAddr'] = zeek_row['dstip']
           argus_row['Dport'] = zeek_row['dsport']
           argus_row['Dur'] = zeek_row['dur']
           argus_row['service'] = zeek_row['service']
           argus_row['trans_depth'] = zeek_row['trans_depth']
           argus_row['res_bdy_len'] = zeek_row['res_bdy_len']
    
    if (argus_row['SrcAddr'] == argus_row['DstAddr'] and argus_row['Sport'] and argus_row['Dport']):
        argus_row['is_sm_ips_ports'] = 1

    if (argus_row['State'] == 'FIN' and argus_row['sTtl'] == '254' and argus_row['dTtl'] == '252'  ):
        argus_row['ct_state_ttl'] = 1
    
    if (argus_row['State'] == 'FIN' and argus_row['sTtl'] == '62' and argus_row['dTtl'] == '252'  ):
        argus_row['ct_state_ttl'] = 1

    if (argus_row['State'] == 'FIN' and argus_row['sTtl'] == '62' and argus_row['dTtl'] == '253'  ):
        argus_row['ct_state_ttl'] = 1

    if (argus_row['State'] == 'FIN' and argus_row['sTtl'] == '63' and argus_row['dTtl'] == '252'  ):
        argus_row['ct_state_ttl'] = 1

    if (argus_row['State'] == 'FIN' and argus_row['sTtl'] == '63' and argus_row['dTtl'] == '253'  ):
        argus_row['ct_state_ttl'] = 1

    if (argus_row['State'] == 'FIN' and argus_row['sTtl'] == '254' and argus_row['dTtl'] == '253'  ):
        argus_row['ct_state_ttl'] = 1
    
    if (argus_row['State'] == 'FIN' and argus_row['sTtl'] == '255' and argus_row['dTtl'] == '252'  ):
        argus_row['ct_state_ttl'] = 1
    
    if (argus_row['State'] == 'FIN' and argus_row['sTtl'] == '255' and argus_row['dTtl'] == '253'  ):
        argus_row['ct_state_ttl'] = 1

    if (argus_row['State'] == 'INT' and argus_row['sTtl'] == '0' and argus_row['dTtl'] == '0'  ):
        argus_row['ct_state_ttl'] = 2

    if (argus_row['State'] == 'INT' and argus_row['sTtl'] == '62' and argus_row['dTtl'] == '0'  ):
        argus_row['ct_state_ttl'] = 2

    if (argus_row['State'] == 'INT' and argus_row['sTtl'] == '254' and argus_row['dTtl'] == '0'  ):
        argus_row['ct_state_ttl'] = 2

    if (argus_row['State'] == 'CON' and argus_row['sTtl'] == '62' and argus_row['dTtl'] == '60'  ):
        argus_row['ct_state_ttl'] = 3

    if (argus_row['State'] == 'CON' and argus_row['sTtl'] == '62' and argus_row['dTtl'] == '252'  ):
        argus_row['ct_state_ttl'] = 3

    if (argus_row['State'] == 'CON' and argus_row['sTtl'] == '62' and argus_row['dTtl'] == '253'  ):
        argus_row['ct_state_ttl'] = 3

    if (argus_row['State'] == 'CON' and argus_row['sTtl'] == '254' and argus_row['dTtl'] == '60'  ):
        argus_row['ct_state_ttl'] = 3

    if (argus_row['State'] == 'CON' and argus_row['sTtl'] == '254' and argus_row['dTtl'] == '252'  ):
        argus_row['ct_state_ttl'] = 3

    if (argus_row['State'] == 'CON' and argus_row['sTtl'] == '254' and argus_row['dTtl'] == '253'  ):
        argus_row['ct_state_ttl'] = 3

    if (argus_row['State'] == 'ACC' and argus_row['sTtl'] == '254' and argus_row['dTtl'] == '252'  ):
        argus_row['ct_state_ttl'] = 4

    if (argus_row['State'] == 'CLO' and argus_row['sTtl'] == '254' and argus_row['dTtl'] == '252'  ):
        argus_row['ct_state_ttl'] = 5

    if (argus_row['State'] == 'REQ' and argus_row['sTtl'] == '254' and argus_row['dTtl'] == '0'  ):
        argus_row['ct_state_ttl'] = 6


    for ftp_row in ftp_data:
        if(ftp_row['user'] != '-' and ftp_row['user'] != '<unknown>' and ftp_row['user'] != 'anonymous' and ftp_row['password'] != '-'):
            if(argus_row['SrcAddr'] == ftp_row['id.orig_h'] and argus_row['Sport'] == ftp_row['id.orig_p'] and argus_row['DstAddr'] == ftp_row['id.resp_h'] and argus_row['Dport'] == ftp_row['id.resp_p']):
                argus_row['is_ftp_login'] = 1

    for ftp_row in ftp_data:
        if(ftp_row['command'] != '-'):
            if(argus_row['SrcAddr'] == ftp_row['id.orig_h'] and argus_row['Sport'] == ftp_row['id.orig_p'] and argus_row['DstAddr'] == ftp_row['id.resp_h'] and argus_row['Dport'] == ftp_row['id.resp_p']):
                argus_row['ct_ftp_cmd'] = argus_row['ct_ftp_cmd'] + 1
    
    for http_row in http_data:
        if(http_row['method'] == 'GET' or http_row['method'] == 'POST'):
            if(argus_row['SrcAddr'] == http_row['id.orig_h'] and argus_row['Sport'] == http_row['id.orig_p'] and argus_row['DstAddr'] == http_row['id.resp_h'] and argus_row['Dport'] == http_row['id.resp_p']):
                argus_row['ct_flw_http_mthd'] = argus_row['ct_flw_http_mthd'] + 1


for indice, row in enumerate(argus_data):
    row['ct_srv_src'] = 0
    row['ct_srv_dst'] = 0
    row['ct_dst_ltm'] = 0
    row['ct_src_ltm'] = 0
    row['ct_src_dport_ltm'] = 0
    row['ct_dst_sport_ltm'] = 0
    row['ct_dst_src_ltm'] = 0

    for i in range(1, min(100, (len(argus_data) - indice))):
        if((argus_data[indice + i]['SrcAddr'] == row['SrcAddr']) and (argus_data[indice + i]['service'] == row['service'])):
            row['ct_srv_src'] = row['ct_srv_src'] + 1
        else:
            row['ct_srv_src'] = 1

        if((argus_data[indice + i]['DstAddr'] == row['DstAddr']) and (argus_data[indice + i]['service'] == row['service'])):
            row['ct_srv_dst'] = row['ct_srv_dst'] + 1
        else:
            row['ct_srv_dst'] = 1

        if((argus_data[indice + i]['DstAddr'] == row['DstAddr']) and (argus_data[indice + i]['LastTime'] == row['LastTime'])):
            row['ct_dst_ltm'] = row['ct_dst_ltm'] + 1
        else:
            row['ct_dst_ltm'] = 1

        if((argus_data[indice + i]['SrcAddr'] == row['SrcAddr']) and (argus_data[indice + i]['LastTime'] == row['LastTime'])):
            row['ct_src_ltm'] = row['ct_src_ltm'] + 1
        else: 
            row['ct_src_ltm'] = 1
        
        if((argus_data[indice + i]['SrcAddr'] == row['SrcAddr']) and (argus_data[indice + i]['LastTime'] == row['LastTime']) and (argus_data[indice + i]['Dport'] == row['Dport'])):
            row['ct_src_dport_ltm'] = row['ct_src_dport_ltm'] + 1
        else:
            row['ct_src_dport_ltm'] = 1

        if((argus_data[indice + i]['DstAddr'] == row['DstAddr']) and (argus_data[indice + i]['LastTime'] == row['LastTime']) and (argus_data[indice + i]['Sport'] == row['Sport'])):
            row['ct_dst_sport_ltm'] = row['ct_dst_sport_ltm'] + 1
        else:
            row['ct_dst_sport_ltm'] = 1

        if((argus_data[indice + i]['DstAddr'] == row['DstAddr']) and (argus_data[indice + i]['LastTime'] == row['LastTime']) and (argus_data[indice + i]['SrcAddr'] == row['SrcAddr'])):
            row['ct_dst_src_ltm'] = row['ct_dst_src_ltm'] + 1
        else:
            row['ct_dst_src_ltm'] = 1


for row in argus_data:
    row['service'] = row.pop('service')

column_names = list(argus_data[0].keys())
column_names.insert(13,column_names.pop(column_names.index('service')))
column_names.insert(24,column_names.pop(column_names.index('trans_depth')))
column_names.insert(25,column_names.pop(column_names.index('res_bdy_len')))
column_names.insert(35,column_names.pop(column_names.index('is_sm_ips_ports')))
column_names.insert(36,column_names.pop(column_names.index('ct_state_ttl')))
column_names.insert(37,column_names.pop(column_names.index('ct_flw_http_mthd')))
column_names.insert(38,column_names.pop(column_names.index('is_ftp_login')))
column_names.insert(39,column_names.pop(column_names.index('ct_ftp_cmd')))
column_names.insert(40,column_names.pop(column_names.index('ct_srv_src')))
column_names.insert(41,column_names.pop(column_names.index('ct_srv_dst')))
column_names.insert(42,column_names.pop(column_names.index('ct_dst_ltm')))
column_names.insert(43,column_names.pop(column_names.index('ct_src_ltm')))
column_names.insert(44,column_names.pop(column_names.index('ct_src_dport_ltm')))
column_names.insert(45,column_names.pop(column_names.index('ct_dst_sport_ltm')))
column_names.insert(46,column_names.pop(column_names.index('ct_dst_src_ltm')))

with open ('combined_data.csv', 'w', newline='') as combined_file:
    writer = csv.DictWriter(combined_file, fieldnames=column_names)
    writer.writeheader()
    writer.writerows(argus_data)