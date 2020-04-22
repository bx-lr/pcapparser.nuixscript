import os
import sys
import shutil

def gui_value_validator(values):
    #print '(v)processing selection', values['processing_selection']
    #print '(v)output path', values['output_path']
    #print '(v)ingest results', values['ingest_results']
    #print '(v)cleanup files', values['cleanup_files']
    op = values['output_path']
    if len(op) < 1:
        CommonDialogs.showWarning('Please provide an output path')
        return False
    if os.path.isfile(op):
        CommonDialogs.showWarning('Please provide a folder')
        return False
    if not os.path.exists(op):
        CommonDialogs.showWarning('Please provide a folder that exists')
        return False
    return True



def gen_gui():
    dialog =  TabbedCustomDialog()
    mytab = dialog.addTab('my_tab_name', 'Pcap Parser Configuration')
    mytab.appendComboBox('processing_selection', 'Processing Selection:', ['All Files', 'Only Selected'])
    mytab.appendDirectoryChooser("output_path", "Output Path:")
    mytab.appendCheckBox("ingest_results", "Ingest results on completion?", True)
    mytab.appendCheckBox("cleanup_files", "Cleanup output files on completion?", True)

    #dialog_items = dialog.toMap()
    dialog.validateBeforeClosing(gui_value_validator)
    dialog.display()

    #if this is true we continue,
    if dialog.getDialogResult() == False:
        sys.exit(-1)
    dialog_items = dialog.toMap()
    #print 'dialog_items', dialog_items
    #print 'ingest_results', dialog_items['ingest_results']
    #print 'output_path', dialog_items['output_path']
    #print 'cleanup_files', dialog_items['cleanup_files']
    #print 'processing_selection', dialog_items['processing_selection']
    #print 'current selected items', currentSelectedItems
    dialog_items['current_selected_items'] = currentSelectedItems
    return dialog_items


def main(worker_side_script_code):
    args = gen_gui()
    #if dialog.getDialogResult == true
    output_path = args['output_path']
    processing_selection = args['processing_selection']
    print processing_selection
    if processing_selection.find('All') > -1:
        items = currentCase.search('mime-type:application/vnd.tcpdump.pcap')
    else:
        items = args['current_selected_items']
    #remove any bad pcap files    
    tmp = []
    for item in items:
        if str(item.type).find('application/vnd.tcpdump.pcap') == -1:
            print 'Invalid pcap, skipping item: ', item
            continue
        tmp.append(item)
    items = tmp
    #get the raw pcap data

    #todo: add try catch on error... have to reload and store source data
    all_pcap_files = wb_get_pcap_data(items)
    #start the dump
    evidence = process_and_dump(all_pcap_files, output_path)
    evidence_container_names = []
    #if set ingest the evidence
    if args['ingest_results']:
        for epath in evidence:
            epath = str(epath)
            processor = currentCase.createProcessor()
            processing_settings = {"processingSettings" : "processText:true", "workerItemCallback" : "python:"+worker_script_code, "extractNamedEntitiesFromTextStripped" : "true", "extractNamedEntitiesFromText" : "true", "extractNamedEntitiesFromProperties": "true", "reportProcessingStatus" : "none" }
            parallel_processing_settings = {"parallelProcessingSettings" : "workerCount:2"}
            processor.setProcessingSettings(processing_settings)
            processor.setParallelProcessingSettings(parallel_processing_settings)
            evidence_container_name = epath.split('\\')[-1].rstrip('\\').rstrip('/')
            evidence_container_desc = 'Evidence container for pcap file ' + evidence_container_name
            print 'Ingesting results:', evidence_container_name
            evidence_container_names.append(evidence_container_name)
            evidence_container = processor.newEvidenceContainer(evidence_container_name, {"description":evidence_container_desc})
            #print dir(evidence_container)
            for f in os.listdir(epath):
                evidence_container.addFile( epath + f )
            #print dir(processor)
            evidence_container.save()
            processor.process()

        root_items = current_case.getRootItems()
        evidence_containers = []
        for ec in root_items:
            if ec.getName() in evidence_container_names:
                evidence_containers.append(ec)

    #   
    #populate metadata....
    #todo: add size totals
    #todo: add tcp stream info
    #todo: add dns info
    #todo: add mac address named entitiy
    #todo: fix output text format

        for ec in evidence_containers:
            print 'Adding metadata to: ', ec.getName()
            items =  ec.getChildren()
            for item in items:
                cm = item.getCustomMetadata()
                pcap_data = []
                size = item.fileSize
                bin = item.binary.getBinaryData()
                for byte in xrange(0, size):
                    tmp = bin.read(byte)
                    tmp = struct.pack('B', tmp)
                    pcap_data.append(struct.unpack('c', tmp)[0])

                pcap_data = ''.join(pcap_data)
                data = pcap_data.split('\n')
                for line in data:
                    if line.find('ts_sec') > -1:
                        date = line.replace('ts_sec: ', '')
                    if line.find('destination mac:') > -1:
                        d_mac = line.replace('destination mac: ', '')
                        cm.put('Destination MAC', d_mac)
                    if line.find('source mac:') > -1:
                        s_mac = line.replace('source mac: ', '')
                        cm.put('Source MAC', s_mac)
                    if line.find('ip_source:') > -1:
                        s_ip = line.replace('ip_source: ', '')
                        cm.put('IP Source', s_ip)
                    if line.find('ip_destination:') > -1:
                        d_ip = line.replace('ip_destination: ', '')
                        cm.put('IP Destination', d_ip)
                    if line.find('incl_len:') > -1:
                        incl_len = line.replace('incl_len: ', '')
                        cm.put('Packet Size', incl_len)

    #
    #clean up files
    #
    if args['cleanup_files']:
        for epath in evidence:
            shutil.rmtree(str(epath))



if __name__ == '__main__':
    print('Must be executed via the Worbench GUI')
    sys.exit(-1)
else:
    #look for our directory to load the GUI java stuff
    #and our worker side scripting stuff
    envars = ['%appdata%', '%programdata%']
    for var in envars:
        instdir = os.path.expandvars(var)
        instdir += '\\Nuix\\Scripts\\PcapParser\\Python\\pcapparser.nuixscript\\'
        if os.path.isdir(instdir):
            dirlist = os.listdir(instdir)
            if 'Nx.jar' in dirlist:
                sys.path.append(instdir+'Nx.jar')
                sys.path.append(instdir)
            else:
                print('Could not find Nx.jar file. Please download to this scripts nuixscript directory')
                sys.exit(-1)
            if 'worker_side_script_code.py' in dirlist:
                fd = open(instdir+'worker_side_script_code.py', 'rb')
                worker_script_code = fd.read()
                fd.close()
            else:
                print('Could not find worker_side_script_code.py file. Please ensure script installed correctly')
                sys.exit(-1)
    #import this outside of any function to maintain global scope
    #and not have import statments throughout the code
    try:
        import com.nuix.nx.dialogs.TabbedCustomDialog as TabbedCustomDialog
    except Exception as e:
        print('Could not find Nx.jar file. Please download to this scripts nuixscript directory')
        print(e)
        sys.exit(-1)
    #import this outside of any function to maintain global scope
    #and not have import statments throughout the code
    try:
        import com.nuix.nx.dialogs.CommonDialogs as CommonDialogs
    except Exception as e:
        print('Could not find Nx.jar file. Please download to this scripts nuixscript directory')
        print(e)
        sys.exit(-1)
    #import this outside of any function to maintain global scope
    #and not have import statments throughout the code
    try:
        from pcap_parser import *
    except Exception as e:
        print('Could not find pcap_parser.py file. Please ensure script installed correctly')
        print(e)
        sys.exit(-1)

    main(worker_script_code)
