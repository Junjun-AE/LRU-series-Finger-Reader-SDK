"""
LRU系列指纹读头管理系统 - 专业版 v5.1 (打包适配版)
现代化仪表板界面设计

修复内容:
1. 线程安全问题 - 所有GUI操作都在主线程执行
2. Widget生命周期管理 - 防止访问已销毁的组件
3. 完善的异常处理和日志记录
4. DLL安全加载机制
5. 资源正确释放
6. 备份文件自动清理
7. 加密解密错误处理
8. ★ PyInstaller打包路径适配 ★
"""

import os
import sys
import ctypes
from ctypes import *
import base64
import json
import time
import threading
import logging
import traceback
from typing import Optional, Dict, List, Tuple, Callable
from datetime import datetime
import queue
import weakref

# ======================= 打包路径适配 =======================
def get_base_path():
    """获取程序基础路径（兼容打包和开发环境）"""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))

def get_resource_path(relative_path=""):
    """获取资源文件路径（DLL等打包进exe的资源）"""
    if getattr(sys, 'frozen', False):
        base = sys._MEIPASS
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    
    if relative_path:
        return os.path.join(base, relative_path)
    return base

BASE_PATH = get_base_path()
RESOURCE_PATH = get_resource_path()
_STYLE_INITIALIZED = False

# ======================= 日志配置 =======================
log_file = os.path.join(BASE_PATH, 'fingerprint_system.log')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(log_file, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
logger.info(f"程序基础路径: {BASE_PATH}")
logger.info(f"资源文件路径: {RESOURCE_PATH}")

# ======================= 加密模块安全导入 =======================
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    logger.warning("cryptography模块未安装，将使用简单编码")
    CRYPTO_AVAILABLE = False

# ======================= Tkinter导入 =======================
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from tkinter.scrolledtext import ScrolledText

# ======================= DLL安全加载 =======================
class DLLLoader:
    """安全的DLL加载器 - 打包适配版"""
    
    def __init__(self):
        self.fp_dll = None
        self.dll_folder = None
        self._load_dlls()
    
    def _get_dll_search_paths(self):
        """获取DLL搜索路径列表"""
        paths = []
        paths.append(RESOURCE_PATH)
        paths.append(BASE_PATH)
        if getattr(sys, 'frozen', False):
            paths.append(os.path.dirname(sys.executable))
        
        seen = set()
        result = []
        for p in paths:
            if p not in seen and os.path.exists(p):
                seen.add(p)
                result.append(p)
        return result
    
    def _load_dlls(self):
        """尝试从多个路径加载DLL"""
        search_paths = self._get_dll_search_paths()
        logger.info(f"DLL搜索路径: {search_paths}")
        
        for folder in search_paths:
            try:
                os.environ['PATH'] = folder + ';' + os.environ.get('PATH', '')
                if hasattr(os, 'add_dll_directory'):
                    try:
                        os.add_dll_directory(folder)
                    except Exception:
                        pass
                
                nbis_path = os.path.join(folder, "nbis64.dll")
                core_path = os.path.join(folder, "fpcorex64.dll")
                fp_path = os.path.join(folder, "fpengine.dll")
                
                logger.info(f"检查DLL: {fp_path}, 存在: {os.path.exists(fp_path)}")
                
                if os.path.exists(fp_path):
                    if os.path.exists(nbis_path):
                        ctypes.WinDLL(nbis_path)
                        logger.info(f"加载 nbis64.dll 成功")
                    if os.path.exists(core_path):
                        ctypes.WinDLL(core_path)
                        logger.info(f"加载 fpcorex64.dll 成功")
                    
                    self.fp_dll = ctypes.WinDLL(fp_path)
                    self.dll_folder = folder
                    self._setup_function_signatures()
                    logger.info(f"DLL加载成功: {folder}")
                    return
                    
            except Exception as e:
                logger.warning(f"从 {folder} 加载DLL失败: {e}")
                continue
        
        logger.error("无法加载指纹设备DLL，设备功能将不可用")
    
    def _setup_function_signatures(self):
        """设置DLL函数签名"""
        if not self.fp_dll:
            return
        try:
            self.fp_dll.OpenDevice.argtypes = [c_int, c_int, c_int]
            self.fp_dll.OpenDevice.restype = c_int
            self.fp_dll.LinkDevice.argtypes = [c_uint32]
            self.fp_dll.LinkDevice.restype = c_int
            self.fp_dll.CloseDevice.argtypes = []
            self.fp_dll.CloseDevice.restype = c_int
            self.fp_dll.SetDevicePassword.argtypes = [c_uint32]
            self.fp_dll.SetDevicePassword.restype = c_int
            self.fp_dll.SetMsgMainHandle.argtypes = [c_void_p]
            self.fp_dll.SetMsgMainHandle.restype = None
            self.fp_dll.SetTimeOut.argtypes = [c_double]
            self.fp_dll.SetTimeOut.restype = None
            self.fp_dll.CaptureImage.argtypes = []
            self.fp_dll.CaptureImage.restype = None
            self.fp_dll.CaptureTemplate.argtypes = []
            self.fp_dll.CaptureTemplate.restype = None
            self.fp_dll.EnrollTemplate.argtypes = []
            self.fp_dll.EnrollTemplate.restype = None
            self.fp_dll.EnrollTemplateCount.argtypes = [c_int]
            self.fp_dll.EnrollTemplateCount.restype = None
            self.fp_dll.GetWorkMsg.argtypes = []
            self.fp_dll.GetWorkMsg.restype = c_int
            self.fp_dll.GetRetMsg.argtypes = []
            self.fp_dll.GetRetMsg.restype = c_int
            self.fp_dll.ReleaseMsg.argtypes = []
            self.fp_dll.ReleaseMsg.restype = c_int
            self.fp_dll.GetTemplateByCap.argtypes = [POINTER(c_ubyte), POINTER(c_int)]
            self.fp_dll.GetTemplateByCap.restype = c_bool
            self.fp_dll.GetTemplateByEnl.argtypes = [POINTER(c_ubyte), POINTER(c_int)]
            self.fp_dll.GetTemplateByEnl.restype = c_bool
            self.fp_dll.GetBase64StrByCap.argtypes = [c_bool, POINTER(c_ubyte)]
            self.fp_dll.GetBase64StrByCap.restype = c_bool
            self.fp_dll.GetBase64StrByEnl.argtypes = [c_bool, POINTER(c_ubyte)]
            self.fp_dll.GetBase64StrByEnl.restype = c_bool
            self.fp_dll.MatchTemplate.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte)]
            self.fp_dll.MatchTemplate.restype = c_int
            self.fp_dll.MatchTemplateOne.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), c_int]
            self.fp_dll.MatchTemplateOne.restype = c_int
            self.fp_dll.MatchTemplateFull.argtypes = [POINTER(c_ubyte), c_int, POINTER(c_ubyte), c_int]
            self.fp_dll.MatchTemplateFull.restype = c_int
            self.fp_dll.MatchBase64Str.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), c_bool]
            self.fp_dll.MatchBase64Str.restype = c_int
            self.fp_dll.GetRawImage.argtypes = [POINTER(c_ubyte), POINTER(c_int)]
            self.fp_dll.GetRawImage.restype = c_bool
            self.fp_dll.GetBmpImage.argtypes = [POINTER(c_ubyte), POINTER(c_int)]
            self.fp_dll.GetBmpImage.restype = c_bool
            self.fp_dll.GetImageSize.argtypes = [POINTER(c_int), POINTER(c_int)]
            self.fp_dll.GetImageSize.restype = c_bool
            self.fp_dll.DrawImage.argtypes = [c_void_p, c_int, c_int]
            self.fp_dll.DrawImage.restype = c_int
            self.fp_dll.GetDeviceModel.argtypes = []
            self.fp_dll.GetDeviceModel.restype = c_uint32
            self.fp_dll.GetDeviceVersion.argtypes = []
            self.fp_dll.GetDeviceVersion.restype = c_byte
            self.fp_dll.GetDeviceSnNum.argtypes = []
            self.fp_dll.GetDeviceSnNum.restype = c_uint
            self.fp_dll.GetDeviceSnStr.argtypes = [c_bool, POINTER(c_ubyte)]
            self.fp_dll.GetDeviceSnStr.restype = c_bool
            self.fp_dll.CheckTemplate.argtypes = [POINTER(c_ubyte), c_int]
            self.fp_dll.CheckTemplate.restype = c_bool
            self.fp_dll.DeviceSoundBeep.argtypes = [c_int]
            self.fp_dll.DeviceSoundBeep.restype = c_bool
        except Exception as e:
            logger.error(f"设置DLL函数签名失败: {e}")
            self.fp_dll = None
    
    @property
    def is_available(self) -> bool:
        return self.fp_dll is not None

dll_loader = DLLLoader()
fp_dll = dll_loader.fp_dll

# ======================= 常量定义 =======================
class FPMessage:
    DEVICE = 1
    PLACE = 2
    LIFT = 3
    CAPTURE = 4
    GENCHAR = 5
    ENRFPT = 6
    NEWIMAGE = 7
    TIMEOUT = 8
    IMGVAL = 9
    ENROLID = 0x10
    VERIFY = 0x11
    IDENTIFY = 0x12

class DeviceConstants:
    RET_OK = 1
    RET_FAIL = 0
    REFTPSIZE = 512
    MATTPSIZE = 256
    SREFTPSIZE = 768
    SMATTPSIZE = 384
    IMGSIZE = 73728
    THRESHOLD = 60
    TEMPLATE_TYPE_REF = "REF_512"
    TEMPLATE_TYPE_MATCH = "MATCH_256"

# ======================= 线程安全工具类 =======================
class ThreadSafeCallback:
    def __init__(self, root: tk.Tk):
        self._root_ref = weakref.ref(root)
        self._lock = threading.Lock()
    
    def call_in_main_thread(self, func: Callable, *args, **kwargs):
        root = self._root_ref()
        if root is None:
            return
        try:
            if threading.current_thread() is threading.main_thread():
                func(*args, **kwargs)
            else:
                root.after(0, lambda: self._safe_call(func, *args, **kwargs))
        except Exception as e:
            logger.error(f"回调执行失败: {e}")
    
    def _safe_call(self, func: Callable, *args, **kwargs):
        try:
            func(*args, **kwargs)
        except tk.TclError as e:
            logger.debug(f"Widget已销毁，忽略回调: {e}")
        except Exception as e:
            logger.error(f"回调执行异常: {e}\n{traceback.format_exc()}")

class WidgetGuard:
    @staticmethod
    def exists(widget) -> bool:
        try:
            if widget is None:
                return False
            if not hasattr(widget, 'winfo_exists'):
                return False
            return widget.winfo_exists()
        except tk.TclError:
            return False
        except Exception:
            return False
    
    @staticmethod
    def safe_config(widget, **kwargs):
        if WidgetGuard.exists(widget):
            try:
                widget.config(**kwargs)
                return True
            except (tk.TclError, Exception):
                pass
        return False
    
    @staticmethod
    def safe_delete(entry_widget, start, end):
        if WidgetGuard.exists(entry_widget):
            try:
                entry_widget.delete(start, end)
                return True
            except (tk.TclError, Exception):
                pass
        return False
    
    @staticmethod
    def safe_insert(entry_widget, index, text):
        if WidgetGuard.exists(entry_widget):
            try:
                entry_widget.insert(index, text)
                return True
            except (tk.TclError, Exception):
                pass
        return False
    
    @staticmethod
    def safe_get(entry_widget, default=""):
        if WidgetGuard.exists(entry_widget):
            try:
                return entry_widget.get()
            except (tk.TclError, Exception):
                pass
        return default

# ======================= 加密工具类 =======================
class DataEncryption:
    def __init__(self, password: str = None, key_file: str = None):
        self.key_file = key_file
        self._cipher = None
        
        if not CRYPTO_AVAILABLE:
            logger.warning("加密模块不可用，使用Base64编码")
            return
        
        try:
            if password:
                self.key = self._derive_key(password)
            elif key_file and os.path.exists(key_file):
                with open(key_file, 'rb') as f:
                    self.key = f.read()
            else:
                self.key = Fernet.generate_key()
            self._cipher = Fernet(self.key)
        except Exception as e:
            logger.error(f"初始化加密模块失败: {e}")
            self._cipher = None
    
    def _derive_key(self, password: str) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'fingerprint_system_2024_v5',
            iterations=100000
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def encrypt_data(self, data: str) -> bytes:
        if self._cipher:
            return self._cipher.encrypt(data.encode('utf-8'))
        return base64.b64encode(data.encode('utf-8'))
    
    def decrypt_data(self, encrypted_data: bytes) -> str:
        try:
            if self._cipher:
                return self._cipher.decrypt(encrypted_data).decode('utf-8')
            return base64.b64decode(encrypted_data).decode('utf-8')
        except InvalidToken:
            logger.error("解密失败：密钥不正确或数据已损坏")
            raise ValueError("解密失败：密钥不正确或数据已损坏")
        except Exception as e:
            logger.error(f"解密失败: {e}")
            raise

# ======================= 指纹设备管理类 =======================
class FingerprintDevice:
    def __init__(self):
        self._is_connected = False
        self._lock = threading.RLock()
        self._device_info = {}
        self._operation_cancelled = False
    
    @property
    def is_connected(self) -> bool:
        with self._lock:
            return self._is_connected
    
    @property
    def device_info(self) -> Dict:
        with self._lock:
            return self._device_info.copy()
    
    def cancel_operation(self):
        self._operation_cancelled = True
    
    def connect(self) -> bool:
        if not fp_dll:
            logger.error("DLL未加载，无法连接设备")
            return False
        
        with self._lock:
            if self._is_connected:
                return True
            try:
                result = fp_dll.OpenDevice(0, 0, 0)
                if result != 1:
                    result = fp_dll.OpenDevice(1, 57600, 1)
                    if result != 1:
                        logger.error("设备连接失败")
                        return False
                
                fp_dll.LinkDevice(0)
                fp_dll.SetTimeOut(30.0)
                try:
                    fp_dll.DeviceSoundBeep(0)
                except Exception:
                    pass
                
                self._get_device_info_unsafe()
                self._is_connected = True
                logger.info("设备连接成功")
                return True
            except Exception as e:
                logger.error(f"连接设备异常: {e}\n{traceback.format_exc()}")
                return False
    
    def _get_device_info_unsafe(self):
        try:
            self._device_info = {
                'serial': fp_dll.GetDeviceSnNum(),
                'model': fp_dll.GetDeviceModel(),
                'version': fp_dll.GetDeviceVersion()
            }
            str_buffer = (c_ubyte * 100)()
            if fp_dll.GetDeviceSnStr(False, str_buffer):
                sn_bytes = bytes(str_buffer)
                idx = sn_bytes.find(b'\x00')
                if idx != -1:
                    self._device_info['serial_str'] = sn_bytes[:idx].decode('utf-8', errors='ignore')
        except Exception as e:
            logger.warning(f"获取设备信息失败: {e}")
    
    def disconnect(self) -> bool:
        with self._lock:
            if not self._is_connected:
                return True
            try:
                if fp_dll:
                    try:
                        fp_dll.ReleaseMsg()
                    except Exception:
                        pass
                    try:
                        fp_dll.CloseDevice()
                    except Exception:
                        pass
                self._is_connected = False
                self._device_info = {}
                logger.info("设备已断开")
                return True
            except Exception as e:
                logger.error(f"断开设备异常: {e}")
                return False
    
    def _process_messages(self, target_msg: int, timeout: int = 30, 
                          callback: Callable[[str], None] = None) -> Tuple[bool, int]:
        self._operation_cancelled = False
        start_time = time.time()
        status_map = {
            FPMessage.PLACE: "请按压手指",
            FPMessage.LIFT: "请抬起手指",
            FPMessage.CAPTURE: "图像采集完成",
            FPMessage.NEWIMAGE: "检测到新图像"
        }
        
        while time.time() - start_time < timeout:
            if self._operation_cancelled:
                logger.info("操作已取消")
                return False, 0
            try:
                with self._lock:
                    if not self._is_connected or not fp_dll:
                        return False, 0
                    msg = fp_dll.GetWorkMsg()
                
                if msg == target_msg:
                    with self._lock:
                        ret = fp_dll.GetRetMsg()
                    return True, ret
                elif msg == FPMessage.TIMEOUT:
                    logger.warning("设备操作超时")
                    return False, msg
                elif msg != 0 and callback and msg in status_map:
                    try:
                        callback(status_map[msg])
                    except Exception as e:
                        logger.debug(f"回调执行失败: {e}")
            except Exception as e:
                logger.error(f"处理消息异常: {e}")
                return False, 0
            time.sleep(0.05)
        
        logger.warning("操作超时")
        return False, 0
    
    def enroll_fingerprint(self, enroll_count: int = 3, timeout: int = 30,
                           callback: Callable[[str], None] = None) -> Tuple[Optional[str], str]:
        with self._lock:
            if not self._is_connected or not fp_dll:
                return None, ""
        try:
            with self._lock:
                fp_dll.EnrollTemplateCount(enroll_count)
            
            success, ret = self._process_messages(FPMessage.ENRFPT, timeout, callback)
            if not success or ret != 1:
                logger.warning(f"指纹登记失败: success={success}, ret={ret}")
                return None, ""
            
            buffer = (c_ubyte * DeviceConstants.REFTPSIZE)()
            size = c_int(DeviceConstants.REFTPSIZE)
            with self._lock:
                success = fp_dll.GetTemplateByEnl(buffer, byref(size))
            
            if success and size.value > 0:
                template = base64.b64encode(bytes(buffer[:size.value])).decode('utf-8')
                logger.info(f"指纹登记成功，模板大小: {size.value}")
                return template, DeviceConstants.TEMPLATE_TYPE_REF
            return None, ""
        except Exception as e:
            logger.error(f"指纹登记异常: {e}\n{traceback.format_exc()}")
            return None, ""
    
    def capture_fingerprint_for_identification(self, timeout: int = 15,
                                                callback: Callable[[str], None] = None) -> Tuple[Optional[str], str]:
        with self._lock:
            if not self._is_connected or not fp_dll:
                return None, ""
        try:
            with self._lock:
                fp_dll.CaptureTemplate()
            
            success, ret = self._process_messages(FPMessage.GENCHAR, timeout, callback)
            if not success or ret != 1:
                logger.warning(f"指纹采集失败: success={success}, ret={ret}")
                return None, ""
            
            buffer = (c_ubyte * DeviceConstants.MATTPSIZE)()
            size = c_int(DeviceConstants.MATTPSIZE)
            with self._lock:
                success = fp_dll.GetTemplateByCap(buffer, byref(size))
            
            if success and size.value > 0:
                template = base64.b64encode(bytes(buffer[:size.value])).decode('utf-8')
                logger.info(f"指纹采集成功，模板大小: {size.value}")
                return template, DeviceConstants.TEMPLATE_TYPE_MATCH
            return None, ""
        except Exception as e:
            logger.error(f"指纹采集异常: {e}\n{traceback.format_exc()}")
            return None, ""
    
    def match_fingerprint(self, match_template: str, ref_template: str,
                          threshold: int = DeviceConstants.THRESHOLD) -> Tuple[bool, int]:
        if not fp_dll:
            return False, 0
        try:
            match_bytes = base64.b64decode(match_template)
            ref_bytes = base64.b64decode(ref_template)
            match_buf = (c_ubyte * len(match_bytes))(*match_bytes)
            ref_buf = (c_ubyte * len(ref_bytes))(*ref_bytes)
            
            with self._lock:
                if len(match_bytes) == 256 and len(ref_bytes) == 512:
                    score = fp_dll.MatchTemplateOne(match_buf, ref_buf, len(ref_bytes))
                elif len(match_bytes) == 512 and len(ref_bytes) == 512:
                    score = fp_dll.MatchTemplateFull(match_buf, len(match_bytes), ref_buf, len(ref_bytes))
                else:
                    score = fp_dll.MatchTemplateOne(match_buf, ref_buf, len(ref_bytes))
            return score >= threshold, score
        except Exception as e:
            logger.error(f"指纹匹配异常: {e}")
            return False, 0
    
    def get_status(self) -> Dict:
        with self._lock:
            return {
                'connected': self._is_connected,
                'device_info': self._device_info.copy(),
                'dll_available': fp_dll is not None
            }

# ======================= 指纹数据管理类 =======================
class FingerprintDataManager:
    MAX_BACKUPS = 10
    MAX_ACTIVITY_LOG = 100
    
    def __init__(self, data_dir: str = "fingerprint_data", 
                 filename: str = "fingerprints.dat",
                 encryption_password: str = "MySecurePassword2024!"):
        if not os.path.isabs(data_dir):
            data_dir = os.path.join(BASE_PATH, data_dir)
        
        os.makedirs(data_dir, exist_ok=True)
        self.data_file = os.path.join(data_dir, filename)
        self.backup_dir = os.path.join(data_dir, "backups")
        os.makedirs(self.backup_dir, exist_ok=True)
        
        logger.info(f"数据目录: {data_dir}")
        logger.info(f"数据文件: {self.data_file}")
        
        self.encryption = DataEncryption(password=encryption_password)
        self._lock = threading.RLock()
        self.fingerprints: List[Dict] = []
        self.activity_log: List[Dict] = []
        self.next_id = 1
        self._load_data()
        self._cleanup_old_backups()
    
    def _load_data(self):
        if not os.path.exists(self.data_file):
            logger.info("数据文件不存在，创建新数据库")
            return
        try:
            with open(self.data_file, 'rb') as f:
                encrypted_data = f.read()
            decrypted = self.encryption.decrypt_data(encrypted_data)
            data = json.loads(decrypted)
            
            if isinstance(data, dict):
                self.fingerprints = data.get('fingerprints', [])
                self.activity_log = data.get('activity_log', [])[-self.MAX_ACTIVITY_LOG:]
            elif isinstance(data, list):
                self.fingerprints = data
            
            if self.fingerprints:
                self.next_id = max(fp.get('id', 0) for fp in self.fingerprints) + 1
            logger.info(f"数据加载成功，共 {len(self.fingerprints)} 条记录")
        except ValueError as e:
            logger.error(f"数据解密失败: {e}")
            self._try_load_backup()
        except json.JSONDecodeError as e:
            logger.error(f"数据格式错误: {e}")
            self._try_load_backup()
        except Exception as e:
            logger.error(f"加载数据失败: {e}\n{traceback.format_exc()}")
    
    def _try_load_backup(self):
        try:
            backups = sorted([f for f in os.listdir(self.backup_dir) if f.endswith('.dat')], reverse=True)
            for backup in backups[:3]:
                backup_path = os.path.join(self.backup_dir, backup)
                try:
                    with open(backup_path, 'rb') as f:
                        data = json.loads(self.encryption.decrypt_data(f.read()))
                    if isinstance(data, dict):
                        self.fingerprints = data.get('fingerprints', [])
                        self.activity_log = data.get('activity_log', [])
                    logger.info(f"从备份恢复成功: {backup}")
                    return
                except Exception:
                    continue
            logger.warning("所有备份恢复失败，使用空数据库")
        except Exception as e:
            logger.error(f"恢复备份失败: {e}")
    
    def _cleanup_old_backups(self):
        try:
            backups = sorted([f for f in os.listdir(self.backup_dir) if f.endswith('.dat')], reverse=True)
            for old_backup in backups[self.MAX_BACKUPS:]:
                try:
                    os.remove(os.path.join(self.backup_dir, old_backup))
                    logger.debug(f"删除旧备份: {old_backup}")
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"清理备份失败: {e}")
    
    def save_data(self) -> bool:
        with self._lock:
            try:
                if os.path.exists(self.data_file):
                    import shutil
                    backup_name = f"backup_{time.strftime('%Y%m%d_%H%M%S')}.dat"
                    shutil.copy2(self.data_file, os.path.join(self.backup_dir, backup_name))
                
                data = {
                    'fingerprints': self.fingerprints,
                    'activity_log': self.activity_log[-self.MAX_ACTIVITY_LOG:],
                    'version': '5.1',
                    'saved_at': time.strftime("%Y-%m-%d %H:%M:%S")
                }
                encrypted = self.encryption.encrypt_data(json.dumps(data, ensure_ascii=False))
                temp_file = self.data_file + '.tmp'
                with open(temp_file, 'wb') as f:
                    f.write(encrypted)
                os.replace(temp_file, self.data_file)
                self._cleanup_old_backups()
                logger.info("数据保存成功")
                return True
            except Exception as e:
                logger.error(f"保存数据失败: {e}\n{traceback.format_exc()}")
                return False
    
    def add_activity(self, action: str, detail: str, success: bool = True):
        with self._lock:
            self.activity_log.append({
                'time': time.strftime("%Y-%m-%d %H:%M:%S"),
                'action': action,
                'detail': detail,
                'success': success
            })
            if len(self.activity_log) > self.MAX_ACTIVITY_LOG:
                self.activity_log = self.activity_log[-self.MAX_ACTIVITY_LOG:]
    
    def add_fingerprint(self, name: str, template: str, template_type: str,
                        permission_level: int, device: FingerprintDevice,
                        check_duplicate: bool = True) -> Tuple[bool, str]:
        with self._lock:
            if not name or not name.strip():
                return False, "姓名不能为空"
            if permission_level not in [1, 2, 3, 4]:
                return False, "权限等级必须是1-4"
            if not template or len(template) < 50:
                return False, "指纹模板无效"
            
            name = name.strip()
            for fp in self.fingerprints:
                if fp['name'].lower() == name.lower():
                    return False, f"姓名 '{name}' 已存在"
            
            if check_duplicate and self.fingerprints:
                for fp in self.fingerprints:
                    try:
                        matched, score = device.match_fingerprint(template, fp['template'])
                        if matched:
                            return False, f"指纹已存在，匹配: {fp['name']} (分数:{score})"
                    except Exception as e:
                        logger.warning(f"指纹匹配检查失败: {e}")
            
            new_id = self.next_id
            self.next_id += 1
            new_fp = {
                "id": new_id,
                "name": name,
                "template": template,
                "template_type": template_type,
                "permission_level": permission_level,
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            self.fingerprints.append(new_fp)
            self.add_activity("登记", f"新增用户: {name}", True)
            
            if self.save_data():
                return True, f"成功添加 {name} (ID:{new_id})"
            else:
                self.fingerprints.pop()
                self.next_id = new_id
                return False, "保存失败"
    
    def find_fingerprint(self, device: FingerprintDevice, match_template: str) -> Optional[Dict]:
        with self._lock:
            if not match_template or not self.fingerprints:
                return None
            best_match = None
            best_score = 0
            for fp in self.fingerprints:
                try:
                    matched, score = device.match_fingerprint(match_template, fp['template'])
                    if matched and score > best_score:
                        best_score = score
                        best_match = fp.copy()
                        best_match['match_score'] = score
                except Exception as e:
                    logger.warning(f"匹配指纹失败: {e}")
            
            if best_match:
                self.add_activity("识别", f"用户: {best_match['name']} (分数:{best_score})", True)
                logger.info(f"指纹识别成功: {best_match['name']}")
            else:
                self.add_activity("识别", "未找到匹配", False)
                logger.info("指纹识别失败：无匹配")
            return best_match
    
    def delete_fingerprint(self, identifier: str) -> Tuple[bool, str]:
        with self._lock:
            for i, fp in enumerate(self.fingerprints):
                if str(fp['id']) == identifier or fp['name'].lower() == identifier.lower():
                    deleted = self.fingerprints.pop(i)
                    self.add_activity("删除", f"删除用户: {deleted['name']}", True)
                    if self.save_data():
                        return True, f"已删除: {deleted['name']}"
                    else:
                        self.fingerprints.insert(i, deleted)
                        return False, "保存失败"
            return False, f"未找到: {identifier}"
    
    def update_fingerprint(self, identifier: str, new_name: str = None,
                           new_permission: int = None) -> Tuple[bool, str]:
        with self._lock:
            for fp in self.fingerprints:
                if str(fp['id']) == identifier or fp['name'].lower() == identifier.lower():
                    old_name = fp['name']
                    if new_name and new_name.strip():
                        new_name = new_name.strip()
                        for other in self.fingerprints:
                            if other['id'] != fp['id'] and other['name'].lower() == new_name.lower():
                                return False, f"姓名 '{new_name}' 已存在"
                        fp['name'] = new_name
                    if new_permission in [1, 2, 3, 4]:
                        fp['permission_level'] = new_permission
                    fp['updated_at'] = time.strftime("%Y-%m-%d %H:%M:%S")
                    self.add_activity("更新", f"更新用户: {old_name} -> {fp['name']}", True)
                    if self.save_data():
                        return True, "更新成功"
                    else:
                        return False, "保存失败"
            return False, f"未找到: {identifier}"
    
    def export_data(self, path: str, password: str = None) -> Tuple[bool, str]:
        with self._lock:
            try:
                data = {
                    'version': '5.1',
                    'export_time': time.strftime("%Y-%m-%d %H:%M:%S"),
                    'count': len(self.fingerprints),
                    'data': self.fingerprints
                }
                json_str = json.dumps(data, ensure_ascii=False, indent=2)
                if password:
                    enc = DataEncryption(password=password)
                    with open(path, 'wb') as f:
                        f.write(enc.encrypt_data(json_str))
                else:
                    with open(path, 'w', encoding='utf-8') as f:
                        f.write(json_str)
                self.add_activity("导出", f"导出 {len(self.fingerprints)} 条", True)
                logger.info(f"数据导出成功: {path}")
                return True, f"已导出到 {path}"
            except Exception as e:
                logger.error(f"导出失败: {e}")
                return False, f"导出失败: {e}"
    
    def import_data(self, path: str, password: str = None, merge: bool = False) -> Tuple[bool, str]:
        with self._lock:
            try:
                if password:
                    enc = DataEncryption(password=password)
                    with open(path, 'rb') as f:
                        json_str = enc.decrypt_data(f.read())
                else:
                    with open(path, 'r', encoding='utf-8') as f:
                        json_str = f.read()
                
                data = json.loads(json_str)
                records = data.get('data', data) if isinstance(data, dict) else data
                if not isinstance(records, list):
                    return False, "数据格式无效"
                
                if merge:
                    count = 0
                    for r in records:
                        if not any(fp['name'].lower() == r.get('name', '').lower() for fp in self.fingerprints):
                            r['id'] = self.next_id
                            self.next_id += 1
                            self.fingerprints.append(r)
                            count += 1
                    self.add_activity("导入", f"合并 {count} 条", True)
                    if self.save_data():
                        return True, f"合并 {count} 条"
                    else:
                        return False, "保存失败"
                else:
                    self.fingerprints = records
                    self.next_id = 1
                    for fp in self.fingerprints:
                        fp['id'] = self.next_id
                        self.next_id += 1
                    self.add_activity("导入", f"导入 {len(records)} 条", True)
                    if self.save_data():
                        return True, f"导入 {len(records)} 条"
                    else:
                        return False, "保存失败"
            except ValueError as e:
                return False, str(e)
            except json.JSONDecodeError:
                return False, "JSON格式错误"
            except Exception as e:
                logger.error(f"导入失败: {e}")
                return False, f"导入失败: {e}"
    
    def get_statistics(self) -> Dict:
        with self._lock:
            stats = {'total': len(self.fingerprints), 'levels': {1: 0, 2: 0, 3: 0, 4: 0}, 'today': 0, 'week': 0}
            now = time.time()
            for fp in self.fingerprints:
                level = fp.get('permission_level', 1)
                if level in stats['levels']:
                    stats['levels'][level] += 1
                try:
                    created = time.mktime(time.strptime(fp['created_at'], "%Y-%m-%d %H:%M:%S"))
                    if now - created < 86400:
                        stats['today'] += 1
                    if now - created < 604800:
                        stats['week'] += 1
                except Exception:
                    pass
            return stats

# ======================= 现代化样式配置 =======================
class Theme:
    PRIMARY = "#6366f1"
    PRIMARY_DARK = "#4f46e5"
    PRIMARY_LIGHT = "#818cf8"
    BG_DARK = "#111827"
    BG_CARD = "#1f2937"
    BG_HOVER = "#374151"
    BG_INPUT = "#374151"
    BG_TABLE = "#111827"
    BG_TABLE_ROW = "#1f2937"
    BG_TABLE_ALT = "#283548"
    SUCCESS = "#22c55e"
    WARNING = "#f59e0b"
    ERROR = "#ef4444"
    INFO = "#3b82f6"
    TEXT_PRIMARY = "#ffffff"
    TEXT_SECONDARY = "#d1d5db"
    TEXT_MUTED = "#9ca3af"
    BORDER = "#4b5563"
    BORDER_LIGHT = "#6b7280"
    FONT_TITLE = ("Microsoft YaHei UI", 28, "bold")
    FONT_HEADING = ("Microsoft YaHei UI", 18, "bold")
    FONT_SUBHEADING = ("Microsoft YaHei UI", 14, "bold")
    FONT_BODY = ("Microsoft YaHei UI", 11)
    FONT_SMALL = ("Microsoft YaHei UI", 9)
    FONT_BUTTON = ("Microsoft YaHei UI", 11, "bold")

# ======================= 自定义组件 =======================
class ModernButton(tk.Canvas):
    def __init__(self, parent, text, command=None, width=120, height=40,
                 bg=Theme.PRIMARY, fg=Theme.TEXT_PRIMARY, icon=None, **kwargs):
        super().__init__(parent, width=width, height=height,
                        bg=parent.cget('bg'), highlightthickness=0, **kwargs)
        self.command = command
        self.bg = bg
        self.fg = fg
        self.text = text
        self.icon = icon
        self.width = width
        self.height = height
        self._enabled = True
        self._draw()
        self.bind('<Enter>', self._on_enter)
        self.bind('<Leave>', self._on_leave)
        self.bind('<Button-1>', self._on_click)
    
    def _draw(self, hover=False):
        self.delete('all')
        if not self._enabled:
            color = "#4a5568"
        elif hover:
            color = self._lighten(self.bg)
        else:
            color = self.bg
        r = 8
        self.create_arc(0, 0, r*2, r*2, start=90, extent=90, fill=color, outline=color)
        self.create_arc(self.width-r*2, 0, self.width, r*2, start=0, extent=90, fill=color, outline=color)
        self.create_arc(0, self.height-r*2, r*2, self.height, start=180, extent=90, fill=color, outline=color)
        self.create_arc(self.width-r*2, self.height-r*2, self.width, self.height, start=270, extent=90, fill=color, outline=color)
        self.create_rectangle(r, 0, self.width-r, self.height, fill=color, outline=color)
        self.create_rectangle(0, r, self.width, self.height-r, fill=color, outline=color)
        display_text = f"{self.icon} {self.text}" if self.icon else self.text
        text_color = self.fg if self._enabled else "#718096"
        self.create_text(self.width/2, self.height/2, text=display_text, fill=text_color, font=Theme.FONT_BUTTON)
    
    def _lighten(self, color):
        try:
            r = int(color[1:3], 16)
            g = int(color[3:5], 16)
            b = int(color[5:7], 16)
            return f"#{min(r+30,255):02x}{min(g+30,255):02x}{min(b+30,255):02x}"
        except Exception:
            return color
    
    def _on_enter(self, event):
        if self._enabled:
            self._draw(True)
            self.config(cursor='hand2')
    
    def _on_leave(self, event):
        self._draw(False)
    
    def _on_click(self, event):
        if self._enabled and self.command:
            try:
                self.command()
            except Exception as e:
                logger.error(f"按钮回调异常: {e}\n{traceback.format_exc()}")
    
    def set_enabled(self, enabled: bool):
        self._enabled = enabled
        self._draw()

class StatCard(tk.Frame):
    def __init__(self, parent, title, value, icon, color=Theme.PRIMARY, **kwargs):
        super().__init__(parent, bg=Theme.BG_CARD, **kwargs)
        self.color = color
        self.title = title
        self.icon_frame = tk.Frame(self, bg=color, width=60)
        self.icon_frame.pack(side='left', fill='y')
        self.icon_frame.pack_propagate(False)
        self.icon_label = tk.Label(self.icon_frame, text=icon, font=("Segoe UI Emoji", 24), bg=color, fg='white')
        self.icon_label.pack(expand=True)
        content = tk.Frame(self, bg=Theme.BG_CARD)
        content.pack(side='left', fill='both', expand=True, padx=15, pady=10)
        self.value_label = tk.Label(content, text=str(value), font=Theme.FONT_HEADING, bg=Theme.BG_CARD, fg=Theme.TEXT_PRIMARY)
        self.value_label.pack(anchor='w')
        self.title_label = tk.Label(content, text=title, font=Theme.FONT_SMALL, bg=Theme.BG_CARD, fg=Theme.TEXT_SECONDARY)
        self.title_label.pack(anchor='w')
    
    def update_value(self, value, color=None):
        if WidgetGuard.exists(self.value_label):
            self.value_label.config(text=str(value))
        if color and WidgetGuard.exists(self.icon_frame):
            self.icon_frame.config(bg=color)
            if WidgetGuard.exists(self.icon_label):
                self.icon_label.config(bg=color)

class ActivityItem(tk.Frame):
    def __init__(self, parent, activity, **kwargs):
        super().__init__(parent, bg=Theme.BG_CARD, **kwargs)
        color = Theme.SUCCESS if activity.get('success', True) else Theme.ERROR
        tk.Frame(self, bg=color, width=4).pack(side='left', fill='y')
        content = tk.Frame(self, bg=Theme.BG_CARD)
        content.pack(side='left', fill='both', expand=True, padx=10, pady=8)
        top = tk.Frame(content, bg=Theme.BG_CARD)
        top.pack(fill='x')
        tk.Label(top, text=activity.get('action', ''), font=Theme.FONT_BODY, bg=Theme.BG_CARD, fg=Theme.TEXT_PRIMARY).pack(side='left')
        time_str = activity.get('time', '')
        if ' ' in time_str:
            time_str = time_str.split(' ')[1]
        tk.Label(top, text=time_str, font=Theme.FONT_SMALL, bg=Theme.BG_CARD, fg=Theme.TEXT_MUTED).pack(side='right')
        tk.Label(content, text=activity.get('detail', ''), font=Theme.FONT_SMALL, bg=Theme.BG_CARD, fg=Theme.TEXT_SECONDARY).pack(anchor='w')

# ======================= 密码验证对话框 =======================
class PasswordDialog:
    def __init__(self, parent, title="权限验证", message="请输入管理员密码以继续操作"):
        self.result = False
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("380x220")
        self.dialog.configure(bg=Theme.BG_CARD)
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() - 380) // 2
        y = (self.dialog.winfo_screenheight() - 220) // 2
        self.dialog.geometry(f"380x220+{x}+{y}")
        header = tk.Frame(self.dialog, bg=Theme.BG_CARD)
        header.pack(fill='x', pady=(20, 10))
        tk.Label(header, text="🔐", font=("Segoe UI Emoji", 32), bg=Theme.BG_CARD).pack()
        tk.Label(header, text=title, font=Theme.FONT_SUBHEADING, bg=Theme.BG_CARD, fg=Theme.TEXT_PRIMARY).pack()
        tk.Label(self.dialog, text=message, font=Theme.FONT_SMALL, bg=Theme.BG_CARD, fg=Theme.TEXT_SECONDARY).pack(pady=(0, 10))
        input_frame = tk.Frame(self.dialog, bg=Theme.BG_INPUT, highlightbackground=Theme.BORDER, highlightthickness=1)
        input_frame.pack(padx=40, fill='x')
        tk.Label(input_frame, text="🔑", font=("Segoe UI Emoji", 12), bg=Theme.BG_INPUT, fg=Theme.TEXT_MUTED).pack(side='left', padx=8)
        self.password_entry = tk.Entry(input_frame, font=Theme.FONT_BODY, bg=Theme.BG_INPUT, fg=Theme.TEXT_PRIMARY, insertbackground=Theme.TEXT_PRIMARY, relief='flat', show="●", width=25)
        self.password_entry.pack(side='left', ipady=10)
        self.password_entry.bind('<Return>', lambda e: self._verify())
        self.password_entry.focus_set()
        self.error_label = tk.Label(self.dialog, text="", font=Theme.FONT_SMALL, bg=Theme.BG_CARD, fg=Theme.ERROR)
        self.error_label.pack(pady=(5, 0))
        btn_frame = tk.Frame(self.dialog, bg=Theme.BG_CARD)
        btn_frame.pack(pady=15)
        ModernButton(btn_frame, "确认", self._verify, width=100, height=36, bg=Theme.PRIMARY).pack(side='left', padx=10)
        ModernButton(btn_frame, "取消", self._cancel, width=100, height=36, bg=Theme.ERROR).pack(side='left', padx=10)
        self.dialog.protocol("WM_DELETE_WINDOW", self._cancel)
        parent.wait_window(self.dialog)
    
    def _verify(self):
        if self.password_entry.get() == "admin":
            self.result = True
            self.dialog.destroy()
        else:
            self.error_label.config(text="密码错误，请重试")
            self.password_entry.delete(0, tk.END)
            self.password_entry.focus_set()
    
    def _cancel(self):
        self.result = False
        self.dialog.destroy()

def verify_password(parent, title="权限验证", message="请输入管理员密码以继续操作") -> bool:
    dialog = PasswordDialog(parent, title, message)
    return dialog.result

# ======================= 登录界面 =======================
class LoginWindow:
    def __init__(self, on_success):
        self.on_success = on_success
        self.root = tk.Tk()
        self.root.title("指纹管理系统")
        self.root.geometry("1000x600")
        self.root.resizable(False, False)
        self.root.configure(bg=Theme.BG_DARK)
        self._center()
        self._setup_ui()
    
    def _center(self):
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() - 1000) // 2
        y = (self.root.winfo_screenheight() - 600) // 2
        self.root.geometry(f"1000x600+{x}+{y}")
    
    def _setup_ui(self):
        left = tk.Frame(self.root, bg=Theme.PRIMARY, width=500)
        left.pack(side='left', fill='y')
        left.pack_propagate(False)
        brand_frame = tk.Frame(left, bg=Theme.PRIMARY)
        brand_frame.place(relx=0.5, rely=0.5, anchor='center')
        tk.Label(brand_frame, text="🔐", font=("Segoe UI Emoji", 72), bg=Theme.PRIMARY, fg='white').pack()
        tk.Label(brand_frame, text="指纹管理系统", font=("Microsoft YaHei UI", 32, "bold"), bg=Theme.PRIMARY, fg='white').pack(pady=(20, 5))
        tk.Label(brand_frame, text="LRU Series Fingerprint Reader", font=("Microsoft YaHei UI", 12), bg=Theme.PRIMARY, fg='#c7d2fe').pack()
        tk.Label(brand_frame, text="Professional Edition v5.1", font=("Microsoft YaHei UI", 10), bg=Theme.PRIMARY, fg='#a5b4fc').pack(pady=(5, 30))
        features = ["✔ 高精度指纹识别", "✔ 加密数据存储", "✔ 多级权限管理", "✔ 完整操作日志"]
        for f in features:
            tk.Label(brand_frame, text=f, font=Theme.FONT_BODY, bg=Theme.PRIMARY, fg='#e0e7ff').pack(anchor='w', pady=2)
        
        right = tk.Frame(self.root, bg=Theme.BG_DARK)
        right.pack(side='right', fill='both', expand=True)
        login_frame = tk.Frame(right, bg=Theme.BG_DARK)
        login_frame.place(relx=0.5, rely=0.5, anchor='center')
        tk.Label(login_frame, text="欢迎回来", font=Theme.FONT_TITLE, bg=Theme.BG_DARK, fg=Theme.TEXT_PRIMARY).pack(anchor='w')
        tk.Label(login_frame, text="请登录您的账户以继续", font=Theme.FONT_BODY, bg=Theme.BG_DARK, fg=Theme.TEXT_SECONDARY).pack(anchor='w', pady=(5, 30))
        tk.Label(login_frame, text="用户名", font=Theme.FONT_BODY, bg=Theme.BG_DARK, fg=Theme.TEXT_SECONDARY).pack(anchor='w', pady=(0, 5))
        user_frame = tk.Frame(login_frame, bg=Theme.BG_INPUT, highlightbackground=Theme.BORDER, highlightthickness=1)
        user_frame.pack(fill='x', pady=(0, 20))
        tk.Label(user_frame, text="👤", font=("Segoe UI Emoji", 14), bg=Theme.BG_INPUT, fg=Theme.TEXT_MUTED).pack(side='left', padx=10)
        self.user_entry = tk.Entry(user_frame, font=Theme.FONT_BODY, bg=Theme.BG_INPUT, fg=Theme.TEXT_PRIMARY, insertbackground=Theme.TEXT_PRIMARY, relief='flat', width=30)
        self.user_entry.pack(side='left', ipady=12)
        self.user_entry.insert(0, "admin")
        tk.Label(login_frame, text="密码", font=Theme.FONT_BODY, bg=Theme.BG_DARK, fg=Theme.TEXT_SECONDARY).pack(anchor='w', pady=(0, 5))
        pass_frame = tk.Frame(login_frame, bg=Theme.BG_INPUT, highlightbackground=Theme.BORDER, highlightthickness=1)
        pass_frame.pack(fill='x', pady=(0, 10))
        tk.Label(pass_frame, text="🔑", font=("Segoe UI Emoji", 14), bg=Theme.BG_INPUT, fg=Theme.TEXT_MUTED).pack(side='left', padx=10)
        self.pass_entry = tk.Entry(pass_frame, font=Theme.FONT_BODY, bg=Theme.BG_INPUT, fg=Theme.TEXT_PRIMARY, insertbackground=Theme.TEXT_PRIMARY, relief='flat', width=30, show="●")
        self.pass_entry.pack(side='left', ipady=12)
        self.pass_entry.bind('<Return>', lambda e: self._login())
        self.error_label = tk.Label(login_frame, text="", font=Theme.FONT_SMALL, bg=Theme.BG_DARK, fg=Theme.ERROR)
        self.error_label.pack(pady=(0, 10))
        ModernButton(login_frame, "登  录", self._login, width=320, height=48, bg=Theme.PRIMARY).pack(pady=(10, 0))
        tk.Label(login_frame, text="默认账号: admin / admin", font=Theme.FONT_SMALL, bg=Theme.BG_DARK, fg=Theme.TEXT_MUTED).pack(pady=(30, 0))
        self.user_entry.focus_set()
    
    def _login(self):
        if self.user_entry.get().strip() == "admin" and self.pass_entry.get() == "admin":
            logger.info("用户登录成功")
            self.root.destroy()
            self.on_success()
        else:
            self.error_label.config(text="用户名或密码错误")
            self.pass_entry.delete(0, tk.END)
    
    def run(self):
        self.root.mainloop()

# ======================= 主应用程序 =======================
class MainApplication:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("指纹管理系统 v5.1")
        self.root.geometry("1400x900")
        self.root.configure(bg=Theme.BG_DARK)
        self.root.minsize(1200, 800)
        self.device = FingerprintDevice()
        self.data_manager = FingerprintDataManager(encryption_password="1323412519")
        self.callback_helper = ThreadSafeCallback(self.root)
        self.current_page = "dashboard"
        self._running = True
        self._active_threads: List[threading.Thread] = []
        self._operation_lock = threading.Lock()
        self._page_widgets = {}
        self._setup_ui()
        self._center()
        self._update_clock()
        self._refresh_dashboard()
        logger.info("应用程序启动完成")
    
    def _center(self):
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() - 1400) // 2
        y = (self.root.winfo_screenheight() - 900) // 2
        self.root.geometry(f"1400x900+{x}+{y}")
    
    def _setup_ui(self):
        self._setup_header()
        main = tk.Frame(self.root, bg=Theme.BG_DARK)
        main.pack(fill='both', expand=True)
        self._setup_sidebar(main)
        self.content = tk.Frame(main, bg=Theme.BG_DARK)
        self.content.pack(side='left', fill='both', expand=True, padx=20, pady=20)
    
    def _setup_header(self):
        header = tk.Frame(self.root, bg=Theme.BG_CARD, height=60)
        header.pack(fill='x')
        header.pack_propagate(False)
        tk.Label(header, text="🔐 指纹管理系统", font=Theme.FONT_SUBHEADING, bg=Theme.BG_CARD, fg=Theme.TEXT_PRIMARY).pack(side='left', padx=20)
        right = tk.Frame(header, bg=Theme.BG_CARD)
        right.pack(side='right', padx=20)
        self.clock_label = tk.Label(right, text="", font=Theme.FONT_BODY, bg=Theme.BG_CARD, fg=Theme.TEXT_SECONDARY)
        self.clock_label.pack(side='left', padx=20)
        self.device_indicator = tk.Label(right, text="● 设备未连接", font=Theme.FONT_BODY, bg=Theme.BG_CARD, fg=Theme.ERROR)
        self.device_indicator.pack(side='left', padx=20)
        tk.Label(right, text="👤 Admin", font=Theme.FONT_BODY, bg=Theme.BG_CARD, fg=Theme.TEXT_PRIMARY).pack(side='left')
    
    def _setup_sidebar(self, parent):
        sidebar = tk.Frame(parent, bg=Theme.BG_CARD, width=220)
        sidebar.pack(side='left', fill='y', padx=(20, 0), pady=20)
        sidebar.pack_propagate(False)
        menus = [
            ("📊", "仪表板", "dashboard", self._show_dashboard),
            ("📌", "设备管理", "device", self._show_device),
            ("", "", "", None),
            ("✋", "指纹登记", "enroll", self._show_enroll),
            ("🔍", "指纹识别", "identify", self._show_identify),
            ("", "", "", None),
            ("📋", "用户管理", "users", self._show_users),
            ("📤", "数据导出", "export", self._show_export),
            ("📥", "数据导入", "import", self._show_import),
        ]
        self.menu_buttons = {}
        for icon, text, key, command in menus:
            if not text:
                tk.Frame(sidebar, bg=Theme.BORDER, height=1).pack(fill='x', padx=15, pady=10)
            else:
                btn = tk.Frame(sidebar, bg=Theme.BG_CARD, cursor='hand2')
                btn.pack(fill='x', padx=10, pady=2)
                inner = tk.Frame(btn, bg=Theme.BG_CARD)
                inner.pack(fill='x', padx=10, pady=10)
                tk.Label(inner, text=icon, font=("Segoe UI Emoji", 14), bg=Theme.BG_CARD, fg=Theme.TEXT_SECONDARY).pack(side='left')
                lbl = tk.Label(inner, text=text, font=Theme.FONT_BODY, bg=Theme.BG_CARD, fg=Theme.TEXT_SECONDARY)
                lbl.pack(side='left', padx=10)
                self.menu_buttons[key] = (btn, inner, lbl)
                for w in [btn, inner, lbl]:
                    w.bind('<Enter>', lambda e, b=btn, i=inner, l=lbl, k=key: self._menu_hover(b, i, l, k, True))
                    w.bind('<Leave>', lambda e, b=btn, i=inner, l=lbl, k=key: self._menu_hover(b, i, l, k, False))
                    w.bind('<Button-1>', lambda e, c=command, k=key: self._menu_click(c, k))
        tk.Frame(sidebar, bg=Theme.BG_CARD).pack(fill='both', expand=True)
        exit_btn = ModernButton(sidebar, "退出系统", self._exit, width=180, height=40, bg=Theme.ERROR, icon="🚪")
        exit_btn.pack(pady=20)
    
    def _menu_hover(self, btn, inner, lbl, key, hover):
        if self.current_page == key:
            return
        color = Theme.BG_HOVER if hover else Theme.BG_CARD
        for w in [btn, inner]:
            WidgetGuard.safe_config(w, bg=color)
        WidgetGuard.safe_config(lbl, bg=color)
    
    def _menu_click(self, command, key):
        if not self._running:
            return
        self.device.cancel_operation()
        try:
            self.root.update_idletasks()
        except (tk.TclError, Exception):
            pass
        self.current_page = key
        for k, (btn, inner, lbl) in self.menu_buttons.items():
            if k == key:
                for w in [btn, inner]:
                    WidgetGuard.safe_config(w, bg=Theme.PRIMARY)
                WidgetGuard.safe_config(lbl, bg=Theme.PRIMARY, fg=Theme.TEXT_PRIMARY)
            else:
                for w in [btn, inner]:
                    WidgetGuard.safe_config(w, bg=Theme.BG_CARD)
                WidgetGuard.safe_config(lbl, bg=Theme.BG_CARD, fg=Theme.TEXT_SECONDARY)
        if command:
            try:
                command()
            except Exception as e:
                logger.error(f"切换页面失败: {e}\n{traceback.format_exc()}")
    
    def _clear_content(self):
        self.device.cancel_operation()
        self._page_widgets = {}
        for w in self.content.winfo_children():
            try:
                if w.winfo_exists():
                    w.destroy()
            except (tk.TclError, Exception):
                pass
    
    def _update_clock(self):
        if not self._running:
            return
        try:
            if WidgetGuard.exists(self.clock_label):
                self.clock_label.config(text=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            self.root.after(1000, self._update_clock)
        except Exception:
            pass
    
    def _update_device_status(self):
        if WidgetGuard.exists(self.device_indicator):
            if self.device.is_connected:
                self.device_indicator.config(text="● 设备已连接", fg=Theme.SUCCESS)
            else:
                self.device_indicator.config(text="● 设备未连接", fg=Theme.ERROR)
    
    def _refresh_dashboard(self):
        if not self._running or self.current_page != "dashboard":
            return
        try:
            stats = self.data_manager.get_statistics()
            if 'stat_cards' in self._page_widgets:
                cards = self._page_widgets['stat_cards']
                if len(cards) >= 4:
                    cards[0].update_value(stats['total'])
                    cards[1].update_value(stats['today'])
                    cards[2].update_value(stats['week'])
                    device_color = Theme.SUCCESS if self.device.is_connected else Theme.ERROR
                    cards[3].update_value("在线" if self.device.is_connected else "离线", device_color)
        except Exception as e:
            logger.debug(f"刷新仪表板失败: {e}")
    
    def _run_in_thread(self, func, callback=None, *args, **kwargs):
        def wrapper():
            result = None
            try:
                result = func(*args, **kwargs)
            except Exception as e:
                logger.error(f"后台任务异常: {e}\n{traceback.format_exc()}")
                result = (False, f"执行错误: {e}")
            if callback and self._running:
                try:
                    self.callback_helper.call_in_main_thread(callback, result)
                except Exception as e:
                    logger.error(f"回调执行失败: {e}")
        thread = threading.Thread(target=wrapper, daemon=True)
        thread.start()
        self._active_threads.append(thread)
        self._active_threads = [t for t in self._active_threads if t.is_alive()]
    
    def _show_dashboard(self):
        self._clear_content()
        self.current_page = "dashboard"
        header = tk.Frame(self.content, bg=Theme.BG_DARK)
        header.pack(fill='x', pady=(0, 20))
        tk.Label(header, text="仪表板", font=Theme.FONT_HEADING, bg=Theme.BG_DARK, fg=Theme.TEXT_PRIMARY).pack(side='left')
        tk.Label(header, text="系统概览与快捷操作", font=Theme.FONT_BODY, bg=Theme.BG_DARK, fg=Theme.TEXT_SECONDARY).pack(side='left', padx=20)
        stats = self.data_manager.get_statistics()
        cards_frame = tk.Frame(self.content, bg=Theme.BG_DARK)
        cards_frame.pack(fill='x', pady=(0, 20))
        card_data = [
            ("总用户数", stats['total'], "👥", Theme.PRIMARY),
            ("今日新增", stats['today'], "📈", Theme.SUCCESS),
            ("本周新增", stats['week'], "📊", Theme.INFO),
            ("设备状态", "在线" if self.device.is_connected else "离线", "📌", Theme.SUCCESS if self.device.is_connected else Theme.ERROR),
        ]
        stat_cards = []
        for i, (title, value, icon, color) in enumerate(card_data):
            card = StatCard(cards_frame, title, value, icon, color)
            card.pack(side='left', fill='both', expand=True, padx=(0 if i == 0 else 10, 0))
            stat_cards.append(card)
        self._page_widgets['stat_cards'] = stat_cards
        main_area = tk.Frame(self.content, bg=Theme.BG_DARK)
        main_area.pack(fill='both', expand=True)
        left = tk.Frame(main_area, bg=Theme.BG_CARD, width=350)
        left.pack(side='left', fill='y', padx=(0, 20))
        left.pack_propagate(False)
        tk.Label(left, text="快捷操作", font=Theme.FONT_SUBHEADING, bg=Theme.BG_CARD, fg=Theme.TEXT_PRIMARY).pack(anchor='w', padx=20, pady=(20, 15))
        actions = [
            ("📌 连接设备", self._quick_connect_device, Theme.PRIMARY),
            ("✋ 快速登记", lambda: self._menu_click(self._show_enroll, "enroll"), Theme.SUCCESS),
            ("🔍 快速识别", lambda: self._menu_click(self._show_identify, "identify"), Theme.INFO),
            ("📋 用户列表", lambda: self._menu_click(self._show_users, "users"), Theme.WARNING),
        ]
        for text, cmd, color in actions:
            btn = ModernButton(left, text, cmd, width=300, height=45, bg=color)
            btn.pack(pady=5, padx=20)
        tk.Label(left, text="权限分布", font=Theme.FONT_SUBHEADING, bg=Theme.BG_CARD, fg=Theme.TEXT_PRIMARY).pack(anchor='w', padx=20, pady=(30, 15))
        levels = [
            ("等级1 - 普通", stats['levels'][1], Theme.TEXT_SECONDARY),
            ("等级2 - 中级", stats['levels'][2], Theme.INFO),
            ("等级3 - 高级", stats['levels'][3], Theme.WARNING),
            ("等级4 - 管理", stats['levels'][4], Theme.ERROR)
        ]
        for name, count, color in levels:
            row = tk.Frame(left, bg=Theme.BG_CARD)
            row.pack(fill='x', padx=20, pady=3)
            tk.Label(row, text=name, font=Theme.FONT_SMALL, bg=Theme.BG_CARD, fg=Theme.TEXT_SECONDARY).pack(side='left')
            tk.Label(row, text=str(count), font=Theme.FONT_BODY, bg=Theme.BG_CARD, fg=color).pack(side='right')
        right = tk.Frame(main_area, bg=Theme.BG_CARD)
        right.pack(side='left', fill='both', expand=True)
        tk.Label(right, text="最近活动", font=Theme.FONT_SUBHEADING, bg=Theme.BG_CARD, fg=Theme.TEXT_PRIMARY).pack(anchor='w', padx=20, pady=(20, 15))
        activities = self.data_manager.activity_log[-10:][::-1]
        if activities:
            for act in activities:
                ActivityItem(right, act).pack(fill='x', padx=15, pady=2)
        else:
            tk.Label(right, text="暂无活动记录", font=Theme.FONT_BODY, bg=Theme.BG_CARD, fg=Theme.TEXT_MUTED).pack(pady=50)
    
    def _quick_connect_device(self):
        if self.device.is_connected:
            messagebox.showinfo("提示", "设备已连接")
            return
        def do_connect():
            return self.device.connect()
        def on_done(success):
            self._update_device_status()
            self._refresh_dashboard()
            if success:
                messagebox.showinfo("成功", "设备连接成功")
            else:
                messagebox.showerror("错误", "设备连接失败，请检查设备")
        self._run_in_thread(do_connect, on_done)
    
    def _show_device(self):
        self._clear_content()
        tk.Label(self.content, text="设备管理", font=Theme.FONT_HEADING, bg=Theme.BG_DARK, fg=Theme.TEXT_PRIMARY).pack(anchor='w', pady=(0, 20))
        card = tk.Frame(self.content, bg=Theme.BG_CARD)
        card.pack(fill='x', pady=(0, 20))
        status_frame = tk.Frame(card, bg=Theme.BG_CARD)
        status_frame.pack(fill='x', padx=30, pady=30)
        icon_color = Theme.SUCCESS if self.device.is_connected else Theme.ERROR
        icon_frame = tk.Frame(status_frame, bg=icon_color, width=80, height=80)
        icon_frame.pack(side='left')
        icon_frame.pack_propagate(False)
        tk.Label(icon_frame, text="📌", font=("Segoe UI Emoji", 32), bg=icon_color, fg='white').pack(expand=True)
        info_frame = tk.Frame(status_frame, bg=Theme.BG_CARD)
        info_frame.pack(side='left', fill='both', expand=True, padx=30)
        status_text = "已连接" if self.device.is_connected else "未连接"
        tk.Label(info_frame, text=f"设备状态: {status_text}", font=Theme.FONT_SUBHEADING, bg=Theme.BG_CARD, fg=icon_color).pack(anchor='w')
        if self.device.is_connected:
            info = self.device.device_info
            tk.Label(info_frame, text=f"序列号: {info.get('serial', 'N/A')}", font=Theme.FONT_BODY, bg=Theme.BG_CARD, fg=Theme.TEXT_SECONDARY).pack(anchor='w', pady=(10, 0))
            tk.Label(info_frame, text=f"型号: {info.get('model', 'N/A')}", font=Theme.FONT_BODY, bg=Theme.BG_CARD, fg=Theme.TEXT_SECONDARY).pack(anchor='w')
            tk.Label(info_frame, text=f"版本: {info.get('version', 'N/A')}", font=Theme.FONT_BODY, bg=Theme.BG_CARD, fg=Theme.TEXT_SECONDARY).pack(anchor='w')
        else:
            tk.Label(info_frame, text="请连接指纹读头设备", font=Theme.FONT_BODY, bg=Theme.BG_CARD, fg=Theme.TEXT_MUTED).pack(anchor='w', pady=(10, 0))
        btn_frame = tk.Frame(status_frame, bg=Theme.BG_CARD)
        btn_frame.pack(side='right')
        if self.device.is_connected:
            ModernButton(btn_frame, "断开连接", self._disconnect_device, width=140, height=45, bg=Theme.ERROR).pack()
        else:
            ModernButton(btn_frame, "连接设备", self._connect_device, width=140, height=45, bg=Theme.SUCCESS).pack()
        help_card = tk.Frame(self.content, bg=Theme.BG_CARD)
        help_card.pack(fill='x')
        tk.Label(help_card, text="📖 使用说明", font=Theme.FONT_SUBHEADING, bg=Theme.BG_CARD, fg=Theme.TEXT_PRIMARY).pack(anchor='w', padx=20, pady=(15, 10))
        tips = ["1. 请确保指纹读头已通过USB连接到电脑", "2. 首次使用可能需要安装设备驱动程序", "3. 连接成功后，设备状态会显示为绿色", "4. 如连接失败，请检查USB接口或更换端口重试"]
        for tip in tips:
            tk.Label(help_card, text=tip, font=Theme.FONT_BODY, bg=Theme.BG_CARD, fg=Theme.TEXT_SECONDARY).pack(anchor='w', padx=20, pady=2)
        tk.Label(help_card, text="", bg=Theme.BG_CARD).pack(pady=10)
    
    def _connect_device(self):
        def do_connect():
            return self.device.connect()
        def on_done(success):
            self._update_device_status()
            if success:
                messagebox.showinfo("成功", "设备连接成功")
            else:
                messagebox.showerror("错误", "设备连接失败，请检查设备连接")
            if self.current_page == "device":
                self._show_device()
            self._refresh_dashboard()
        self._run_in_thread(do_connect, on_done)
    
    def _disconnect_device(self):
        if self.device.disconnect():
            self._update_device_status()
            messagebox.showinfo("成功", "设备已断开")
            if self.current_page == "device":
                self._show_device()
            self._refresh_dashboard()
        else:
            messagebox.showerror("错误", "断开设备失败")
    
    def _show_enroll(self):
        self._clear_content()
        tk.Label(self.content, text="指纹登记", font=Theme.FONT_HEADING, bg=Theme.BG_DARK, fg=Theme.TEXT_PRIMARY).pack(anchor='w', pady=(0, 20))
        card = tk.Frame(self.content, bg=Theme.BG_CARD)
        card.pack(fill='both', expand=True)
        form_frame = tk.Frame(card, bg=Theme.BG_CARD)
        form_frame.place(relx=0.5, rely=0.5, anchor='center')
        tk.Label(form_frame, text="✋", font=("Segoe UI Emoji", 64), bg=Theme.BG_CARD).pack(pady=(0, 20))
        name_frame = tk.Frame(form_frame, bg=Theme.BG_INPUT, highlightbackground=Theme.BORDER, highlightthickness=1)
        name_frame.pack(fill='x', pady=10)
        tk.Label(name_frame, text="👤", font=("Segoe UI Emoji", 14), bg=Theme.BG_INPUT, fg=Theme.TEXT_MUTED).pack(side='left', padx=10)
        enroll_name = tk.Entry(name_frame, font=Theme.FONT_BODY, bg=Theme.BG_INPUT, fg=Theme.TEXT_PRIMARY, insertbackground=Theme.TEXT_PRIMARY, relief='flat', width=35)
        enroll_name.pack(side='left', ipady=12)
        enroll_name.insert(0, "请输入姓名")
        enroll_name.bind('<FocusIn>', lambda e: enroll_name.delete(0, tk.END) if enroll_name.get() == "请输入姓名" else None)
        self._page_widgets['enroll_name'] = enroll_name
        level_frame = tk.Frame(form_frame, bg=Theme.BG_CARD)
        level_frame.pack(fill='x', pady=10)
        tk.Label(level_frame, text="权限等级:", font=Theme.FONT_BODY, bg=Theme.BG_CARD, fg=Theme.TEXT_SECONDARY).pack(side='left')
        enroll_level = tk.StringVar(value="1")
        self._page_widgets['enroll_level'] = enroll_level
        for i in range(1, 5):
            rb = tk.Radiobutton(level_frame, text=f"等级{i}", variable=enroll_level, value=str(i), font=Theme.FONT_BODY, bg=Theme.BG_CARD, fg=Theme.TEXT_PRIMARY, selectcolor=Theme.BG_INPUT, activebackground=Theme.BG_CARD, activeforeground=Theme.TEXT_PRIMARY)
            rb.pack(side='left', padx=10)
        enroll_status = tk.Label(form_frame, text="", font=Theme.FONT_BODY, bg=Theme.BG_CARD, fg=Theme.TEXT_SECONDARY)
        enroll_status.pack(pady=20)
        self._page_widgets['enroll_status'] = enroll_status
        ModernButton(form_frame, "开始登记", self._start_enroll, width=200, height=50, bg=Theme.PRIMARY, icon="✋").pack(pady=10)
    
    def _start_enroll(self):
        if not self.device.is_connected:
            messagebox.showwarning("提示", "请先连接设备")
            return
        name_widget = self._page_widgets.get('enroll_name')
        level_widget = self._page_widgets.get('enroll_level')
        status_widget = self._page_widgets.get('enroll_status')
        if not WidgetGuard.exists(name_widget):
            return
        name = WidgetGuard.safe_get(name_widget, "").strip()
        if not name or name == "请输入姓名":
            messagebox.showwarning("提示", "请输入姓名")
            return
        level = int(level_widget.get()) if level_widget else 1
        WidgetGuard.safe_config(status_widget, text="请按压手指...", fg=Theme.WARNING)
        current_page = self.current_page
        operation_id = id(status_widget) if status_widget else 0
        def status_callback(msg):
            if not self._running or self.current_page != current_page:
                return
            current_status = self._page_widgets.get('enroll_status')
            if current_status is None or id(current_status) != operation_id:
                return
            self.callback_helper.call_in_main_thread(lambda: WidgetGuard.safe_config(current_status, text=msg))
        def do_enroll():
            try:
                template, ttype = self.device.enroll_fingerprint(callback=status_callback)
                if template:
                    return self.data_manager.add_fingerprint(name, template, ttype, level, self.device)
                return False, "指纹采集失败"
            except Exception as e:
                logger.error(f"登记异常: {e}")
                return False, f"登记异常: {e}"
        def on_done(result):
            try:
                success, msg = result
            except Exception:
                success, msg = False, "结果解析错误"
            if self.current_page != current_page:
                if self._running:
                    def show_msg():
                        try:
                            if success:
                                messagebox.showinfo("成功", msg)
                            else:
                                messagebox.showerror("失败", msg)
                        except Exception:
                            pass
                    try:
                        self.root.after(50, show_msg)
                    except Exception:
                        pass
                return
            current_status = self._page_widgets.get('enroll_status')
            current_name = self._page_widgets.get('enroll_name')
            if current_status is None or id(current_status) != operation_id:
                if success:
                    messagebox.showinfo("成功", msg)
                else:
                    messagebox.showerror("失败", msg)
                return
            if success:
                WidgetGuard.safe_config(current_status, text=f"✔ {msg}", fg=Theme.SUCCESS)
                WidgetGuard.safe_delete(current_name, 0, tk.END)
                WidgetGuard.safe_insert(current_name, 0, "请输入姓名")
                messagebox.showinfo("成功", msg)
                self._refresh_dashboard()
            else:
                WidgetGuard.safe_config(current_status, text=f"✗ {msg}", fg=Theme.ERROR)
                messagebox.showerror("失败", msg)
        self._run_in_thread(do_enroll, on_done)
    
    def _show_identify(self):
        self._clear_content()
        self._page_widgets['is_identifying'] = False
        tk.Label(self.content, text="指纹识别", font=Theme.FONT_HEADING, bg=Theme.BG_DARK, fg=Theme.TEXT_PRIMARY).pack(anchor='w', pady=(0, 20))
        card = tk.Frame(self.content, bg=Theme.BG_CARD)
        card.pack(fill='both', expand=True)
        center = tk.Frame(card, bg=Theme.BG_CARD)
        center.place(relx=0.5, rely=0.5, anchor='center')
        tk.Label(center, text="🔍", font=("Segoe UI Emoji", 72), bg=Theme.BG_CARD).pack(pady=(0, 20))
        identify_status = tk.Label(center, text="点击按钮开始识别", font=Theme.FONT_SUBHEADING, bg=Theme.BG_CARD, fg=Theme.TEXT_SECONDARY)
        identify_status.pack(pady=10)
        self._page_widgets['identify_status'] = identify_status
        result_frame = tk.Frame(center, bg=Theme.BG_CARD)
        result_frame.pack(pady=20)
        self._page_widgets['identify_result_frame'] = result_frame
        ModernButton(center, "开始识别", self._start_identify, width=200, height=50, bg=Theme.INFO, icon="🔍").pack(pady=10)
    
    def _start_identify(self):
        if not self.device.is_connected:
            messagebox.showwarning("提示", "请先连接设备")
            return
        status_widget = self._page_widgets.get('identify_status')
        result_frame = self._page_widgets.get('identify_result_frame')
        if not WidgetGuard.exists(result_frame):
            return
        for w in result_frame.winfo_children():
            w.destroy()
        WidgetGuard.safe_config(status_widget, text="请按压手指...", fg=Theme.WARNING)
        self._page_widgets['is_identifying'] = True
        current_page = self.current_page
        def status_callback(msg):
            if self._running and self.current_page == current_page and self._page_widgets.get('is_identifying'):
                self.callback_helper.call_in_main_thread(lambda: WidgetGuard.safe_config(status_widget, text=msg))
        def do_identify():
            template, _ = self.device.capture_fingerprint_for_identification(callback=status_callback)
            self._page_widgets['is_identifying'] = False
            if template:
                return self.data_manager.find_fingerprint(self.device, template), None
            return None, "指纹采集失败"
        def on_done(result):
            match_result, error = result
            self._show_identify_result(match_result, error)
        self._run_in_thread(do_identify, on_done)
    
    def _show_identify_result(self, result, error=None):
        status_widget = self._page_widgets.get('identify_status')
        result_frame = self._page_widgets.get('identify_result_frame')
        if not WidgetGuard.exists(result_frame):
            if result:
                messagebox.showinfo("识别成功", f"✔ 身份验证通过\n\n姓名: {result['name']}\n权限等级: {result['permission_level']}")
            else:
                msg = error if error else "未找到匹配的指纹"
                messagebox.showwarning("识别失败", f"✗ 身份验证失败\n\n{msg}")
            return
        for w in result_frame.winfo_children():
            w.destroy()
        if result:
            WidgetGuard.safe_config(status_widget, text="✔ 识别成功", fg=Theme.SUCCESS)
            result_card = tk.Frame(result_frame, bg=Theme.BG_INPUT, highlightbackground=Theme.SUCCESS, highlightthickness=2)
            result_card.pack(pady=10, ipadx=30, ipady=15)
            tk.Label(result_card, text=f"👤 {result['name']}", font=Theme.FONT_SUBHEADING, bg=Theme.BG_INPUT, fg=Theme.TEXT_PRIMARY).pack()
            tk.Label(result_card, text=f"权限等级: {result['permission_level']}", font=Theme.FONT_BODY, bg=Theme.BG_INPUT, fg=Theme.TEXT_SECONDARY).pack()
            tk.Label(result_card, text=f"登记时间: {result['created_at']}", font=Theme.FONT_SMALL, bg=Theme.BG_INPUT, fg=Theme.TEXT_MUTED).pack()
            if 'match_score' in result:
                tk.Label(result_card, text=f"匹配分数: {result['match_score']}", font=Theme.FONT_SMALL, bg=Theme.BG_INPUT, fg=Theme.SUCCESS).pack()
            messagebox.showinfo("识别成功", f"✔ 身份验证通过\n\n姓名: {result['name']}\n权限等级: {result['permission_level']}")
        else:
            WidgetGuard.safe_config(status_widget, text="✗ 识别失败", fg=Theme.ERROR)
            msg = error if error else "未找到匹配的指纹"
            tk.Label(result_frame, text=msg, font=Theme.FONT_BODY, bg=Theme.BG_CARD, fg=Theme.ERROR).pack()
            messagebox.showwarning("识别失败", f"✗ 身份验证失败\n\n{msg}")
    
    def _show_users(self):
        global _STYLE_INITIALIZED
        self._clear_content()
        header = tk.Frame(self.content, bg=Theme.BG_DARK)
        header.pack(fill='x', pady=(0, 20))
        tk.Label(header, text="用户管理", font=Theme.FONT_HEADING, bg=Theme.BG_DARK, fg=Theme.TEXT_PRIMARY).pack(side='left')
        tk.Label(header, text=f"共 {len(self.data_manager.fingerprints)} 条记录", font=Theme.FONT_BODY, bg=Theme.BG_DARK, fg=Theme.TEXT_SECONDARY).pack(side='left', padx=20)
        btn_frame = tk.Frame(header, bg=Theme.BG_DARK)
        btn_frame.pack(side='right')
        ModernButton(btn_frame, "刷新", self._show_users, width=80, height=35, bg=Theme.PRIMARY, icon="🔄").pack(side='left', padx=5)
        ModernButton(btn_frame, "搜索", self._search_user, width=80, height=35, bg=Theme.INFO, icon="🔎").pack(side='left', padx=5)
        ModernButton(btn_frame, "编辑", self._edit_user, width=80, height=35, bg=Theme.WARNING, icon="✏️").pack(side='left', padx=5)
        ModernButton(btn_frame, "删除", self._delete_user, width=80, height=35, bg=Theme.ERROR, icon="🗑️").pack(side='left', padx=5)
        table_frame = tk.Frame(self.content, bg=Theme.BG_CARD, highlightbackground=Theme.BORDER, highlightthickness=1)
        table_frame.pack(fill='both', expand=True)
        if not _STYLE_INITIALIZED:
            try:
                style = ttk.Style()
                style.theme_use('clam')
                style.configure("Treeview", background=Theme.BG_TABLE_ROW, foreground=Theme.TEXT_PRIMARY, fieldbackground=Theme.BG_TABLE_ROW, rowheight=45, font=Theme.FONT_BODY)
                style.configure("Treeview.Heading", background=Theme.BG_INPUT, foreground=Theme.TEXT_PRIMARY, font=Theme.FONT_SUBHEADING, relief='flat')
                style.map("Treeview", background=[('selected', Theme.PRIMARY)], foreground=[('selected', Theme.TEXT_PRIMARY)])
                _STYLE_INITIALIZED = True
                logger.info("Treeview样式初始化完成")
            except Exception as e:
                logger.error(f"样式配置失败: {e}")
        columns = ("ID", "姓名", "权限等级", "模板类型", "创建时间")
        try:
            user_tree = ttk.Treeview(table_frame, columns=columns, show='headings', selectmode='browse')
            self._page_widgets['user_tree'] = user_tree
        except Exception as e:
            logger.error(f"创建Treeview失败: {e}")
            return
        col_config = [("ID", 80, 'center'), ("姓名", 180, 'center'), ("权限等级", 120, 'center'), ("模板类型", 150, 'center'), ("创建时间", 200, 'center')]
        for col, width, anchor in col_config:
            user_tree.heading(col, text=col)
            user_tree.column(col, width=width, anchor=anchor, minwidth=width)
        scrollbar = ttk.Scrollbar(table_frame, orient='vertical', command=user_tree.yview)
        user_tree.configure(yscrollcommand=scrollbar.set)
        user_tree.pack(side='left', fill='both', expand=True, padx=(10, 0), pady=10)
        scrollbar.pack(side='right', fill='y', pady=10, padx=(0, 5))
        user_tree.tag_configure('oddrow', background=Theme.BG_TABLE_ROW)
        user_tree.tag_configure('evenrow', background=Theme.BG_TABLE_ALT)
        for i, fp in enumerate(self.data_manager.fingerprints):
            tag = 'evenrow' if i % 2 == 0 else 'oddrow'
            user_tree.insert('', 'end', values=(fp['id'], fp['name'], f"等级 {fp['permission_level']}", fp.get('template_type', 'N/A'), fp['created_at']), tags=(tag,))
        stats_frame = tk.Frame(self.content, bg=Theme.BG_CARD)
        stats_frame.pack(fill='x', pady=(10, 0))
        stats = self.data_manager.get_statistics()
        stats_text = f"📊 权限分布:  等级1: {stats['levels'][1]}人  |  等级2: {stats['levels'][2]}人  |  等级3: {stats['levels'][3]}人  |  等级4: {stats['levels'][4]}人"
        tk.Label(stats_frame, text=stats_text, font=Theme.FONT_BODY, bg=Theme.BG_CARD, fg=Theme.TEXT_SECONDARY).pack(pady=10)
    
    def _search_user(self):
        keyword = simpledialog.askstring("搜索", "请输入搜索关键词 (姓名/ID):")
        if not keyword:
            return
        user_tree = self._page_widgets.get('user_tree')
        if not WidgetGuard.exists(user_tree):
            return
        results = [fp for fp in self.data_manager.fingerprints if keyword.lower() in fp['name'].lower() or keyword in str(fp['id'])]
        for item in user_tree.get_children():
            user_tree.delete(item)
        if results:
            for i, fp in enumerate(results):
                tag = 'evenrow' if i % 2 == 0 else 'oddrow'
                user_tree.insert('', 'end', values=(fp['id'], fp['name'], f"等级 {fp['permission_level']}", fp.get('template_type', 'N/A'), fp['created_at']), tags=(tag,))
            messagebox.showinfo("搜索结果", f"找到 {len(results)} 条匹配记录\n\n点击\"刷新\"按钮可恢复显示全部记录")
        else:
            messagebox.showinfo("搜索结果", "未找到匹配记录")
            self._show_users()
    
    def _edit_user(self):
        user_tree = self._page_widgets.get('user_tree')
        if not WidgetGuard.exists(user_tree):
            return
        selected = user_tree.selection()
        if not selected:
            messagebox.showwarning("提示", "请先在列表中选择要编辑的记录")
            return
        if not verify_password(self.root, "编辑用户", "编辑用户信息需要管理员权限"):
            return
        item = user_tree.item(selected[0])
        user_id = str(item['values'][0])
        current_name = item['values'][1]
        current_level = item['values'][2].replace("等级 ", "")
        edit_win = tk.Toplevel(self.root)
        edit_win.title("编辑用户")
        edit_win.geometry("400x250")
        edit_win.configure(bg=Theme.BG_CARD)
        edit_win.resizable(False, False)
        edit_win.transient(self.root)
        edit_win.grab_set()
        edit_win.update_idletasks()
        x = (edit_win.winfo_screenwidth() - 400) // 2
        y = (edit_win.winfo_screenheight() - 250) // 2
        edit_win.geometry(f"400x250+{x}+{y}")
        tk.Label(edit_win, text="编辑用户信息", font=Theme.FONT_SUBHEADING, bg=Theme.BG_CARD, fg=Theme.TEXT_PRIMARY).pack(pady=(20, 15))
        name_frame = tk.Frame(edit_win, bg=Theme.BG_CARD)
        name_frame.pack(fill='x', padx=30, pady=5)
        tk.Label(name_frame, text="姓名:", font=Theme.FONT_BODY, bg=Theme.BG_CARD, fg=Theme.TEXT_SECONDARY, width=8, anchor='e').pack(side='left')
        name_entry = tk.Entry(name_frame, font=Theme.FONT_BODY, bg=Theme.BG_INPUT, fg=Theme.TEXT_PRIMARY, insertbackground=Theme.TEXT_PRIMARY, width=25)
        name_entry.pack(side='left', padx=10, ipady=5)
        name_entry.insert(0, current_name)
        level_frame = tk.Frame(edit_win, bg=Theme.BG_CARD)
        level_frame.pack(fill='x', padx=30, pady=5)
        tk.Label(level_frame, text="权限:", font=Theme.FONT_BODY, bg=Theme.BG_CARD, fg=Theme.TEXT_SECONDARY, width=8, anchor='e').pack(side='left')
        level_var = tk.StringVar(value=current_level)
        level_combo = ttk.Combobox(level_frame, textvariable=level_var, values=["1", "2", "3", "4"], state="readonly", width=22)
        level_combo.pack(side='left', padx=10)
        def do_save():
            new_name = name_entry.get().strip()
            new_level = int(level_var.get())
            success, msg = self.data_manager.update_fingerprint(user_id, new_name if new_name != current_name else None, new_level if str(new_level) != current_level else None)
            if success:
                messagebox.showinfo("成功", msg)
                edit_win.destroy()
                self._show_users()
                self._refresh_dashboard()
            else:
                messagebox.showerror("错误", msg)
        btn_frame = tk.Frame(edit_win, bg=Theme.BG_CARD)
        btn_frame.pack(pady=25)
        ModernButton(btn_frame, "保存", do_save, width=100, height=38, bg=Theme.SUCCESS).pack(side='left', padx=10)
        ModernButton(btn_frame, "取消", edit_win.destroy, width=100, height=38, bg=Theme.ERROR).pack(side='left', padx=10)
    
    def _delete_user(self):
        user_tree = self._page_widgets.get('user_tree')
        if not WidgetGuard.exists(user_tree):
            return
        selected = user_tree.selection()
        if not selected:
            messagebox.showwarning("提示", "请先在列表中选择要删除的记录")
            return
        if not verify_password(self.root, "删除用户", "删除用户需要管理员权限"):
            return
        item = user_tree.item(selected[0])
        user_id, name = str(item['values'][0]), item['values'][1]
        if messagebox.askyesno("确认删除", f"确定要删除用户 {name} (ID:{user_id}) 吗？\n\n此操作不可恢复！"):
            success, msg = self.data_manager.delete_fingerprint(user_id)
            if success:
                messagebox.showinfo("成功", msg)
                self._show_users()
                self._refresh_dashboard()
            else:
                messagebox.showerror("错误", msg)
    
    def _show_export(self):
        self._clear_content()
        tk.Label(self.content, text="数据导出", font=Theme.FONT_HEADING, bg=Theme.BG_DARK, fg=Theme.TEXT_PRIMARY).pack(anchor='w', pady=(0, 20))
        card = tk.Frame(self.content, bg=Theme.BG_CARD)
        card.pack(fill='both', expand=True)
        center = tk.Frame(card, bg=Theme.BG_CARD)
        center.place(relx=0.5, rely=0.5, anchor='center')
        tk.Label(center, text="📤", font=("Segoe UI Emoji", 64), bg=Theme.BG_CARD).pack(pady=(0, 20))
        tk.Label(center, text=f"当前共有 {len(self.data_manager.fingerprints)} 条记录可导出", font=Theme.FONT_BODY, bg=Theme.BG_CARD, fg=Theme.TEXT_SECONDARY).pack(pady=10)
        export_encrypt = tk.BooleanVar(value=False)
        self._page_widgets['export_encrypt'] = export_encrypt
        tk.Checkbutton(center, text="加密导出文件", variable=export_encrypt, font=Theme.FONT_BODY, bg=Theme.BG_CARD, fg=Theme.TEXT_PRIMARY, selectcolor=Theme.BG_INPUT, activebackground=Theme.BG_CARD).pack(pady=10)
        ModernButton(center, "选择保存位置", self._do_export, width=200, height=50, bg=Theme.PRIMARY, icon="📤").pack(pady=20)
    
    def _do_export(self):
        if not verify_password(self.root, "数据导出", "导出数据需要管理员权限"):
            return
        path = filedialog.asksaveasfilename(title="导出数据", defaultextension=".json", filetypes=[("JSON文件", "*.json"), ("所有文件", "*.*")])
        if not path:
            return
        password = None
        export_encrypt = self._page_widgets.get('export_encrypt')
        if export_encrypt and export_encrypt.get():
            password = simpledialog.askstring("密码", "请输入导出文件的加密密码:", show='*')
            if not password:
                return
        success, msg = self.data_manager.export_data(path, password)
        if success:
            messagebox.showinfo("成功", msg)
        else:
            messagebox.showerror("错误", msg)
    
    def _show_import(self):
        self._clear_content()
        tk.Label(self.content, text="数据导入", font=Theme.FONT_HEADING, bg=Theme.BG_DARK, fg=Theme.TEXT_PRIMARY).pack(anchor='w', pady=(0, 20))
        card = tk.Frame(self.content, bg=Theme.BG_CARD)
        card.pack(fill='both', expand=True)
        center = tk.Frame(card, bg=Theme.BG_CARD)
        center.place(relx=0.5, rely=0.5, anchor='center')
        tk.Label(center, text="📥", font=("Segoe UI Emoji", 64), bg=Theme.BG_CARD).pack(pady=(0, 20))
        tk.Label(center, text="选择要导入的数据文件", font=Theme.FONT_BODY, bg=Theme.BG_CARD, fg=Theme.TEXT_SECONDARY).pack(pady=10)
        import_encrypt = tk.BooleanVar(value=False)
        self._page_widgets['import_encrypt'] = import_encrypt
        tk.Checkbutton(center, text="文件已加密", variable=import_encrypt, font=Theme.FONT_BODY, bg=Theme.BG_CARD, fg=Theme.TEXT_PRIMARY, selectcolor=Theme.BG_INPUT, activebackground=Theme.BG_CARD).pack(pady=5)
        import_merge = tk.BooleanVar(value=True)
        self._page_widgets['import_merge'] = import_merge
        tk.Checkbutton(center, text="合并到现有数据 (否则替换)", variable=import_merge, font=Theme.FONT_BODY, bg=Theme.BG_CARD, fg=Theme.TEXT_PRIMARY, selectcolor=Theme.BG_INPUT, activebackground=Theme.BG_CARD).pack(pady=5)
        ModernButton(center, "选择文件", self._do_import, width=200, height=50, bg=Theme.INFO, icon="📥").pack(pady=20)
    
    def _do_import(self):
        if not verify_password(self.root, "数据导入", "导入数据需要管理员权限"):
            return
        path = filedialog.askopenfilename(title="导入数据", filetypes=[("JSON文件", "*.json"), ("数据文件", "*.dat"), ("所有文件", "*.*")])
        if not path:
            return
        password = None
        import_encrypt = self._page_widgets.get('import_encrypt')
        if import_encrypt and import_encrypt.get():
            password = simpledialog.askstring("密码", "请输入文件的解密密码:", show='*')
            if not password:
                return
        import_merge = self._page_widgets.get('import_merge')
        merge = import_merge.get() if import_merge else True
        if not merge and self.data_manager.fingerprints:
            if not messagebox.askyesno("警告", "替换模式将清除现有数据，确定继续吗？"):
                return
        success, msg = self.data_manager.import_data(path, password, merge)
        if success:
            messagebox.showinfo("成功", msg)
            self._refresh_dashboard()
        else:
            messagebox.showerror("错误", msg)
    
    def _exit(self):
        if messagebox.askyesno("退出", "确定要退出系统吗？"):
            logger.info("用户退出程序")
            self._running = False
            self.device.cancel_operation()
            if self.device.is_connected:
                self.device.disconnect()
            for thread in self._active_threads:
                thread.join(timeout=0.5)
            self.root.destroy()
    
    def run(self):
        self.root.protocol("WM_DELETE_WINDOW", self._exit)
        self.root.mainloop()

# ======================= 主程序入口 =======================
def main():
    logger.info("=" * 50)
    logger.info("指纹管理系统 v5.1 启动")
    logger.info(f"运行模式: {'打包环境' if getattr(sys, 'frozen', False) else '开发环境'}")
    logger.info(f"程序路径: {BASE_PATH}")
    logger.info(f"资源路径: {RESOURCE_PATH}")
    logger.info("=" * 50)
    
    def on_login_success():
        app = MainApplication()
        app.run()
    
    LoginWindow(on_login_success).run()

if __name__ == "__main__":
    main()