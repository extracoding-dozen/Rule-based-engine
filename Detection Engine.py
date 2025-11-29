from procmon_parser import ProcmonLogsReader
import os
import re
from abc import ABC, abstractmethod
from typing import Set
import threading
from queue import Queue, Empty
import time


class ProcessSource(ABC):
    def __init__(self, source_path: str):
        self._source_path = source_path
    
    # Свойства, которые должны быть у наследника
    @property
    @abstractmethod
    def pid(self): pass
    
    @property
    @abstractmethod
    def path(self): pass
    
    @property
    @abstractmethod
    def name(self): pass
    
    @property
    @abstractmethod
    def operation(self): pass
    
    @property
    @abstractmethod
    def cmd(self): pass

    @abstractmethod
    def __next__(self): pass
    
    @abstractmethod
    def close(self): pass
    
    def __iter__(self): return self
    def __enter__(self): return self
    def __exit__(self, exc_type, exc_val, exc_tb): self.close()

class PMLProcessSource(ProcessSource):
    def __init__(self, source_path: str):
        super().__init__(source_path)
        if not os.path.exists(source_path):
            raise FileNotFoundError(f"Source file path is incorrect {source_path}")

        self._file_handle = open(source_path, "rb")
        self._log_parser = ProcmonLogsReader(self._file_handle)    
        self._current_process = None

    def __next__(self):
        try:
            self._current_process = next(self._log_parser)
            return self._current_process
        except StopIteration:
            self._current_process = None
            raise StopIteration
    
    @property
    def pid(self):
        return self._current_process.process.pid if self._current_process else None
    
    @property
    def path(self):
        return self._current_process.path if self._current_process else None
    
    @property
    def name(self):
        return self._current_process.process.process_name if self._current_process else None
    
    @property
    def operation(self):
        return self._current_process.operation if self._current_process else None
    
    @property
    def cmd(self):
        return self._current_process.details.get('Command line') if self._current_process else None
        
    def close(self):
        if self._file_handle:
            self._file_handle.close()
            self._file_handle = None 



class Malware(ABC):
    def __init__(self, flagList : list, pid : int, name : str):
        self._name = name
        self._pid = pid
        self._detected_flags: Set[str] = set(flagList)

    @abstractmethod
    def isMalware(self) -> bool:
        pass

    @abstractmethod
    def __ior__(self, other):
        pass

    @abstractmethod
    def __str__(self) -> str:
        pass

    @property
    def pid(self) -> int:
        return self._pid
    
    @property
    @abstractmethod
    def status(self) -> int:
        pass


class ConcreticRansomwareMalware(Malware):
    __FLAG_MAPPING__ = {
        "malware_network_activity": "MNA", # Сетевая активность
        "malware_cmd_activity": "MCA",     # Активность в командной строке
        "encrypting_user_files": "EUF",    # Шифрование файлов пользователя
        "renaming_user_files": "RUF",      # Переименование файлов пользователя
        "malware_regedit_values": "MRV",   # Запись в реестр
        "writing_user_instructions": "WUI", # Создание инструкций для пользователя (например, записки с требованием выкупа)
    }

    TYPE_NAME = 'Agressive ransomware'

    def __init__(self, flaglist : list, pid : int, name : str):
        super().__init__(flaglist, pid, name)
        for flag_string, attr_name in self.__FLAG_MAPPING__.items():
            setattr(self, attr_name, flag_string in self._detected_flags)
        self.malvFlag = 0 # 0 - безвредно, 1 - подозрительно, 2 - вредоносно

    
    def isMalware(self):
        if self.MNA or (self.MCA and (self.EUF or self.RUF or self.MRV or self.WUI)) or\
              (self.EUF and self.MRV and self.WUI) or (self.MCA and self.RUF):
            self.malvFlag = 2
        elif (self.EUF and self.RUF) or self.WUI or (self.MRV and (self.EUF or self.RUF)):
            self.malvFlag = 1
    
    @property
    def status(self) -> int:
        return self.malvFlag
    
    def __ior__(self, other):
        self.WUI = self.WUI or other.WUI
        self.MNA = self.MNA or other.MNA
        self.MCA = self.MCA or other.MCA
        self.EUF = self.EUF or other.EUF
        self.RUF = self.RUF or other.RUF
        self.MRV = self.MRV or other.MRV
        self.isMalware()
        return self
    
    def __str__(self) -> str:
        res = ''
        res += f'The proccess with pid {self._pid} and name {self._name} is '
        if self.malvFlag == 0:
            res += 'normal\n'
        elif self.malvFlag == 1:
            res += 'suspicious\n'
        else:
            res += 'malicious\n'
        res += f'Expected type: {self.TYPE_NAME}\n'
        res += f'Process is {"" if self.MNA else "not"} connecting to malicious hosts\n'
        res += f'Process is {"" if self.MCA else "not"} running cmd with malicious arguments\n'
        res += f'Process is {"" if self.EUF else "not"} encripting user files\n'
        res += f'Process is {"" if self.RUF else "not"} remaiming user files\n'
        res += f'Process is {"" if self.MRV else "not"} creating malicious regedit values\n'
        res += f'Process is {"" if self.WUI else "not"} writing readmes how to pay foreclosure\n'
        return res


        

class Detector(ABC):
    def __init__(self):
        self.__currect = None
    
    @abstractmethod
    def detect(self, process : ProcessSource = None) -> Malware: pass

    @abstractmethod
    def set_process_source(self, source : ProcessSource): pass


class ConcreticRansomwareDetector(Detector):
    def __init__(self):
        super().__init__()
        self._networking_counter = dict()
        self._FORBIDDEN_ADDRESSES = frozenset(['vwp7696.webpack.hosteurope.de:https',
            '2.103.209.35.bc.googleusercontent.com:https',
            'srv1.ikmagazine.nl:https',
            'gators.ru:https',
            'chah.savviihq.com:https',
            '101.99.77.144:https',
            'ip-160-153-131-189.ip.secureserver.net:https',
            'ing.r1.websupport.sk:https',
            '180.136.102.34.bc.googleusercontent.com:https',
            'world-319.fr.planethoster.net:https',
            'soccmel.sgwebitaly.it:https',
            '239.211.214.35.bc.googleusercontent.com:https',
            'indaix-poseidon.de:https',
            'ip-166-62-108-43.ip.secureserver.net:https',
            '192.237.192.175:https',
            '104.27.173.109:https',
            'ec2-3-88-95-32.compute-1.amazonaws.com:https',
            '172.67.138.91:https',
            'dedi3486.your-server.de:https',
            '2040.wp.34sp.com:https',
            '217-160-0-18.elastic-ssl.ui-r.com:https',
            'lrv1.globehosting.net:https',
            'revo2.w3b.it:https',
            '11.56.157.185.anleggsregister.agnitio.no:https',
            'chi108.greengeeks.net:https',
            '104.31.76.205:https',
            'ip-160-153-133-193.ip.secureserver.net:https',
            'box5503.bluehost.com:https',
            '199.16.172.213:https',
            'csaballoons.com:https',
            'cyberfarm.dotserv.com:https',
            '217-160-0-208.elastic-ssl.ui-r.com:https',
            '172.67.207.210:https',
            's9.gestiondeservidor.com:https',
            'www4.servers58.com:https',
            '82-214-136-24.itsa.net.pl:https',
            'static-148-95-24-46.ipcom.comunitel.net:https',
            '95-165-137-165.static.spd-mgts.ru:https',
            '45.60.22.109:https',
            'www.irizar.com:https',
            'server01.platzer-werbung.de:https',
            'dedi3093545.eu.raiolanetworks.com:https',
            'ns2.hostdown.es:https',
            'a23-37-124-8.deploy.static.akamaitechnologies.com:http',
            'linux57.unoeuro.com:https',
            'crt.sectigo.com:http',
            'serve.versacreative.com:https',
            'ec2-35-170-173-134.compute-1.amazonaws.com:https',
            'ns527890.ip-192-99-7.net:https',
            'ti-01.overtheweb.nl:https',
            'ec2-52-11-37-152.us-west-2.compute.amazonaws.com:https',
            '167.99.54.169:https',
            'vh33.sweb.ru:https',
            'box5121.bluehost.com:https',
            'web-f588402d.lsh.hostnet.nl:https',
            'server18.hostwhitelabel.com:https',
            'ec2-3-125-197-172.eu-central-1.compute.amazonaws.com:https',
            'oliver.exonhost.com:https',
            '5.180.185.169:https',
            '217-160-0-84.elastic-ssl.ui-r.com:https',
            'ns3146141.ip-51-89-7.eu:https',
            'ip118.ip-54-36-201.eu:https',
            'earth.verasoni.com:https',
            'premium76-1.web-hosting.com:https',
            'cl01.hiperactive.net:https',
            '104.27.187.170:https',
            'wpiix5-2.rumahweb.com:https',
            '104.18.60.24:https',
            '972953.vps-10.com:https',
            'res5.mijnplesk.com:https',
            '37.202.7.169:https',
            '51-15-159-75.rev.poneytelecom.eu:https',
            'li1485-84.members.linode.com:https',
            '134.119.88.129:https',
            'inspot-srv1.oderland.com:https',
            'web11.mydevil.net:https',
            'webhosting-cluster.transip.nl:https',
            'web410.default-host.net:https',
            '67.227.226.240:https',
            'a64c2b794233c60a6.awsglobalaccelerator.com:https',
            '80.240.20.142.vultr.com:https',
            'ns.forextimes.ru:https',
            '176.126.61.245.sky-net.com.ua:https',
            '172.67.142.212:https',
            'box5551.bluehost.com:https',
            '154.71.185.35.bc.googleusercontent.com:https',
            'vh251.sweb.ru:https',
            '104.18.10.5:https',
            '158.25.214.35.bc.googleusercontent.com:https',
            '82.94.246.8:https',
            'trillian.ispgateway.de:https',
            'tux419.loginserver.ch:https',
            '23.185.0.2:https',
            'hm8202.locaweb.com.br:https',
            'server.publicompserver.de:https',
            'dedi642.your-server.de:https',
            '92.204.68.14:https',
            '217-160-0-87.elastic-ssl.ui-r.com:https',
            'cluster028.hosting.ovh.net:https',
            'titan.geekstorage.com:https',
            '104.247.81.13:https',
            '53.151.233.35.bc.googleusercontent.com:https',
            '172.67.129.195:https',
            '104.24.103.93:https',
            's215.webhostingserver.nl:https',
            'ec2-52-14-1-58.us-east-2.compute.amazonaws.com:https',
            'linux33.unoeuro.com:https',
            'ec2-100-21-184-71.us-west-2.compute.amazonaws.com:https',
            'host5.server.ae:https',
            '217-160-0-237.elastic-ssl.ui-r.com:https',
            '102.122.185.35.bc.googleusercontent.com:https',
            '172.67.158.193:https',
            '217-160-0-92.elastic-ssl.ui-r.com:https',
            'vps228.keurigonline.nl:https',
            '163-172-24-64.rev.poneytelecom.eu:https',
            'box2262.bluehost.com:https',
            's51-www.ogicom.net:https',
            'eden6.ncsrv.de:https',
            'ec2-34-237-37-253.compute-1.amazonaws.com:https',
            '64.70.194.103:https',
            'ip-184-168-131-241.ip.secureserver.net:https',
            'web2.atznet.dk:https',
            '204.11.56.48:https',
            '67.225.161.117:https',
            's007.cyon.net:https',
            'server67.hosting.reg.ru:https',
            '154.86.216.242:https',
            's23.internetwerk.de:https',
            'domainparking.ru:https',
            'box5556.bluehost.com:https',
            '192-254-186-190.unifiedlayer.com:https',
            'hd1.sitew.com:https',
            '82.62.209.35.bc.googleusercontent.com:https',
            'ip-166-62-110-213.ip.secureserver.net:https',
            '67.225.188.83:https',
            '218.78.209.35.bc.googleusercontent.com:https',
            '103-23-22-248.isi.cloud.id:https',
            '172.67.196.62:https',
            'box398.bluehost.com:https',
            '104.28.12.75:https']
        )
        self._USER_FILE_NAME = '1c67b99-readme.txt'
        self._REGEDIT_PATH = 'HKCU\\Software\\recfg'
        self._USER_FILE_EXTENSIONS = frozenset([
            ".pdf",
            ".doc",
            ".docx",
            ".txt",
            ".rtf",
            ".odt",
            ".xls",
            ".xlsx",
            ".csv",
            ".ppt",
            ".pptx",
            ".odp",
            ".pages",
            ".key",
            ".numbers",
            ".tex",
            ".djvu",
            ".epub",
            ".fb2",
            ".mobi",
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".bmp",
            ".tiff",
            ".tif",
            ".svg",
            ".heic",
            ".webp",
            ".psd",
            ".ai",
            ".raw",
            ".ico",
            ".mp3",
            ".wav",
            ".wma",
            ".aac",
            ".ogg",
            ".flac",
            ".m4a",
            ".aiff",
            ".mid",
            ".midi",
            ".mp4",
            ".avi",
            ".mkv",
            ".mov",
            ".wmv",
            ".flv",
            ".webm",
            ".mpeg",
            ".mpg",
            ".3gp",
            ".zip",
            ".rar",
            ".7z",
            ".tar",
            ".gz",
            ".bz2",
            ".iso",
            ".dmg",
            ".html",
            ".htm",
            ".css",
            ".js",
            ".json",
            ".xml",
            ".mht",
            ".accdb",
            ".mdb",
            ".db",
            ".sql",]
        )
        self._DELETING_SHADOWS_COMMAND = 'vssadmin.exe Delete Shadows /All /Quiet'
        self._DISABLING_RECOVERY_COMMAND = 'bcdedit /set {default} recoveryenabled No'
        self._IGNORING_FAILURES_COMMAND = 'bcdedit /set {default} bootstatuspolicy ignoreallfailures'
        self._WHITE_LIST = frozenset(['System'])
        
    def detect(self, process : ProcessSource = None) -> ConcreticRansomwareMalware:
        self.__currect = process
        if not self.__currect:
            raise TypeError
        if self.__currect.name in self._WHITE_LIST:
            return None
        if "TCP" in self.__currect.operation:
            if (self.__currect.path.split('>'))[1].strip() in self._FORBIDDEN_ADDRESSES:
                self._networking_counter[self.__currect.pid] = self._networking_counter.get(self.__currect.pid, 0) + 1
                if self._networking_counter[self.__currect.pid] >= 3:
                    return ConcreticRansomwareMalware(["malware_network_activity"], self.__currect.pid, self.__currect.name)
        if self.__currect.operation == "WriteFile":
            if self._USER_FILE_NAME in self.__currect.path:
                return ConcreticRansomwareMalware(["writing_user_instructions"], self.__currect.pid, self.__currect.name)
            for expression in self._USER_FILE_EXTENSIONS:
                if expression in self.__currect.path:
                    return ConcreticRansomwareMalware(["encrypting_user_files"], self.__currect.pid, self.__currect.name)

        if self.__currect.operation == "RegSetValue":
            if self._REGEDIT_PATH in self.__currect.path:
                return ConcreticRansomwareMalware(["malware_regedit_values"], self.__currect.pid, self.__currect.name)
        if self.__currect.operation == "SetRenameInformationFile":
            for expression in self._USER_FILE_EXTENSIONS:
                if expression in self.__currect.path:
                    return ConcreticRansomwareMalware(["renaming_user_files"], self.__currect.pid, self.__currect.name)
        if self.__currect.operation == 'Process_Create':
            if 'cmd' in self.__currect.path.lower():
                if self._DISABLING_RECOVERY_COMMAND in self.__currect.cmd or \
                self._IGNORING_FAILURES_COMMAND in self.__currect.cmd or \
                self._DELETING_SHADOWS_COMMAND in self.__currect.cmd:
                    return ConcreticRansomwareMalware(['malware_cmd_activity'], self.__currect.pid, self.__currect.name)
        return None
    def set_process_source(self, source : ProcessSource):
        if not source:
            raise TypeError
        self.__currect = source
    

class Analiser:
    def __init__(self, process_source : ProcessSource, detection_logics : list[Detector]):
        self.__detection_logics = detection_logics
        self.__source = process_source
        self.__malwares = dict() 
        self._lock = threading.Lock()
        self._results_queue = Queue()
        self._stop_event = threading.Event()
        self._processor_thread = threading.Thread(
            target=self._background_processor,
            daemon=True 
        )
        self._detected_pids = set()

    def _background_processor(self):
        trap = False
        while not self._stop_event.is_set() or not trap:
            pid_to_delete = []
            if self._stop_event.is_set():
                trap = True
            with self._lock:
                for pid in list(self.__malwares.keys()):
                    for malware in self.__malwares[pid]:
                        if malware.status == 2: # Вредоносный
                            self._detected_pids.add(malware.pid)
                            self._results_queue.put(malware)
                            pid_to_delete.append(malware.pid)
                        if malware.status == 1 and trap:
                            self._results_queue.put(malware)
                for pid in pid_to_delete:
                    del self.__malwares[pid]
            time.sleep(0.1)


    def analize_system(self):
        self._processor_thread.start()
        for _ in self.__source:
            for detector in self.__detection_logics:
                potential_malware = detector.detect(self.__source)
                with self._lock:
                    if potential_malware:
                        if potential_malware.pid in self._detected_pids:
                            continue
                        self.__malwares.setdefault(self.__source.pid, [potential_malware])
                        merged = False
                        for i in range(len(self.__malwares[self.__source.pid])):
                            if type(self.__malwares[self.__source.pid][i]) is type(potential_malware):
                                self.__malwares[self.__source.pid][i] |= potential_malware
                                merged = True
                        if not merged:
                            self.__malwares[self.__source.pid].append(potential_malware)
            while True:
                try:
                    yield self._results_queue.get_nowait()
                except Empty:
                    break
        self._stop_event.set()
        self._processor_thread.join()
        while True:
            try:
                yield self._results_queue.get_nowait()
            except Empty:
                break

def main(): 
    det = ConcreticRansomwareDetector()
    p = PMLProcessSource("Logfile_4.PML")
    analize = Analiser(p, [det])
    for malware in analize.analize_system():
        if malware.status == 2:
            print("Detected and blocked!!!\n", malware)
        elif malware.status == 1:
            print("Suspicious and redirected to SOC!!!\n", malware)

if __name__ == "__main__":
    main()