import csv
notice_data = []
with open("./notice.log", "r") as zeek_file:
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
        notice_data.append(row)

for row in notice_data:
    row['ts'] = float(row['ts'])
    row['ts'] = int(row['ts'])


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


for row in argus_data:
    for key, value in row.items():
        if value == '':
            row[key] = '0'

for argus_row in argus_data:
    
    argus_row['service'] = '-'
    argus_row['trans_depth'] = 0
    argus_row['res_bdy_len'] = 0

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

for argus_row in argus_data:
    argus_row['Tactic'] = "-"
    argus_row['Technique'] = "-"
    start_range = argus_row['StartTime'] - 1
    end_range = argus_row['StartTime'] + 1
    for notice_row in notice_data:
        note = notice_row['note']
        note_split = note.split('::')
        tactic = note_split[1].strip()
        sub = notice_row['sub']
        sub_split = sub.split(' ')
        technique = ''
        technique1 = ''
        technique2 = ''
        for index, value in enumerate(sub_split):
            if(value == "+"):
                technique2 = sub_split[index + 1]
        technique1 = sub_split[0].strip()
        if(technique1[0] == "T"):
            if(technique2 != ""):
                technique = technique1 + '/' + technique2
            else: 
                technique = technique1

        if(argus_row['SrcAddr'] == notice_row['id.orig_h'] and 
           argus_row['Sport'] == notice_row['id.orig_p'] and
           argus_row['DstAddr'] == notice_row['id.resp_h'] and
           argus_row['Dport'] == notice_row['id.resp_p'] and 
           argus_row['StartTime'] == notice_row['ts']): 
           if(argus_row['Tactic'] == "-"):
            argus_row['Tactic'] = tactic
           if(argus_row['Tactic'] != "-"):
               if tactic not in argus_row['Tactic']:
                   argus_row['Tactic'] = argus_row['Tactic'] + "/" + tactic
           if(argus_row['Technique'] == "-"):
            argus_row['Technique'] = technique
           if(argus_row['Technique'] != "-"):
               if technique not in argus_row['Technique']:
                   argus_row['Technique'] = argus_row['Technique'] + " / " + technique

        elif(argus_row['SrcAddr'] == notice_row['id.orig_h'] and 
           argus_row['Sport'] == notice_row['id.orig_p'] and
           argus_row['DstAddr'] == notice_row['id.resp_h'] and
           argus_row['Dport'] == notice_row['id.resp_p'] and  
           start_range <= notice_row['ts'] <= end_range):
            if(argus_row['Tactic'] == "-"):
                argus_row['Tactic'] = tactic
            if(argus_row['Tactic'] != "-"):
                if tactic not in argus_row['Tactic']:
                    argus_row['Tactic'] = argus_row['Tactic'] + "/" + tactic
            if(argus_row['Technique'] == "-"):
                argus_row['Technique'] = technique
            if(argus_row['Technique'] != "-"):
                if technique not in argus_row['Technique']:
                    argus_row['Technique'] = argus_row['Technique'] + " / " + technique

for row in argus_data:
    row['service'] = row.pop('service')

column_names = list(argus_data[0].keys())
column_names.insert(13,column_names.pop(column_names.index('service')))
column_names.insert(24,column_names.pop(column_names.index('trans_depth')))
column_names.insert(25,column_names.pop(column_names.index('res_bdy_len')))
column_names.insert(36,column_names.pop(column_names.index('Tactic')))
column_names.insert(37,column_names.pop(column_names.index('Technique')))

with open ('notice_data.csv', 'w', newline='') as combined_file:
    writer = csv.DictWriter(combined_file, fieldnames=column_names)
    writer.writeheader()
    writer.writerows(argus_data)