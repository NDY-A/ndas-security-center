using System.Runtime.InteropServices;

namespace Aegis.App.Services;

public sealed class TrayIconService : IDisposable
{
    private const uint TrayCallbackMessage = 0x8000 + 1;
    private const uint TrayIconId = 1;
    private const uint NIM_ADD = 0;
    private const uint NIM_MODIFY = 1;
    private const uint NIM_DELETE = 2;
    private const uint NIF_MESSAGE = 0x01;
    private const uint NIF_ICON = 0x02;
    private const uint NIF_TIP = 0x04;
    private const uint NIF_INFO = 0x10;
    private const uint NIIF_INFO = 0x01;
    private const uint IMAGE_ICON = 1;
    private const uint LR_LOADFROMFILE = 0x10;
    private const uint LR_DEFAULTSIZE = 0x40;
    private const uint IDI_APPLICATION = 32512;
    private const uint MF_STRING = 0x00;
    private const uint MF_DEFAULT = 0x1000;
    private const uint MF_SEPARATOR = 0x800;
    private const uint TPM_RIGHTBUTTON = 0x02;
    private const uint TPM_RETURNCMD = 0x100;
    private const int WM_NULL = 0x0000;
    private const int WM_LBUTTONDBLCLK = 0x0203;
    private const int WM_RBUTTONUP = 0x0205;
    private const int WM_CONTEXTMENU = 0x007B;
    private const int ID_SHOW = 1001;
    private const int ID_EXIT = 1002;

    private static readonly WindowProcDelegate WindowProcCallback = WindowProc;
    private static TrayIconService? _current;

    private readonly Action _onOpen;
    private readonly Action _onExit;
    private readonly string _tooltip;
    private readonly uint _taskbarCreatedMessage;
    private string _className = string.Empty;
    private IntPtr _hostWindow;
    private IntPtr _icon;
    private bool _ownsIcon;
    private bool _classRegistered;
    private bool _disposed;

    public TrayIconService(string iconPath, string tooltip, Action onOpen, Action onExit)
    {
        _onOpen = onOpen;
        _onExit = onExit;
        _tooltip = tooltip.Length > 127 ? tooltip[..127] : tooltip;
        _taskbarCreatedMessage = RegisterWindowMessageW("TaskbarCreated");
        _current = this;

        try
        {
            if (!CreateHostWindow())
            {
                throw new InvalidOperationException("托盘宿主窗口创建失败。");
            }

            _icon = LoadTrayIcon(iconPath);
            if (_icon == IntPtr.Zero)
            {
                throw new InvalidOperationException("托盘图标加载失败。");
            }

            var addData = CreateData(NIF_MESSAGE | NIF_ICON | NIF_TIP);
            if (!Shell_NotifyIconW(NIM_ADD, ref addData))
            {
                throw new InvalidOperationException("Shell_NotifyIcon 添加图标失败。");
            }
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    public void ShowNotification(string title, string message)
    {
        if (_disposed || _hostWindow == IntPtr.Zero)
        {
            return;
        }

        var data = CreateData(NIF_INFO);
        data.szInfoTitle = title.Length > 63 ? title[..63] : title;
        data.szInfo = message.Length > 255 ? message[..255] : message;
        data.dwInfoFlags = NIIF_INFO;
        data.uTimeoutOrVersion = 10000;
        Shell_NotifyIconW(NIM_MODIFY, ref data);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        if (_hostWindow != IntPtr.Zero)
        {
            var data = CreateData(0);
            Shell_NotifyIconW(NIM_DELETE, ref data);
        }

        if (_icon != IntPtr.Zero && _ownsIcon)
        {
            DestroyIcon(_icon);
        }

        _icon = IntPtr.Zero;

        if (_hostWindow != IntPtr.Zero)
        {
            DestroyWindow(_hostWindow);
            _hostWindow = IntPtr.Zero;
        }

        if (_classRegistered)
        {
            UnregisterClassW(_className, GetModuleHandleW(null));
            _classRegistered = false;
        }

        if (ReferenceEquals(_current, this))
        {
            _current = null;
        }
    }

    private bool CreateHostWindow()
    {
        var instance = GetModuleHandleW(null);
        _className = "NDAS.TrayHost." + Guid.NewGuid().ToString("N");
        var windowClass = new WNDCLASSEXW
        {
            cbSize = (uint)Marshal.SizeOf<WNDCLASSEXW>(),
            lpfnWndProc = Marshal.GetFunctionPointerForDelegate(WindowProcCallback),
            hInstance = instance,
            lpszClassName = _className
        };

        if (RegisterClassExW(ref windowClass) == 0)
        {
            throw new InvalidOperationException($"RegisterClassEx 失败，Win32 错误码 {Marshal.GetLastWin32Error()}。");
        }

        _classRegistered = true;
        _hostWindow = CreateWindowExW(
            0,
            _className,
            "NDAS Tray Host",
            0,
            0,
            0,
            0,
            0,
            IntPtr.Zero,
            IntPtr.Zero,
            instance,
            IntPtr.Zero);

        if (_hostWindow == IntPtr.Zero)
        {
            throw new InvalidOperationException($"CreateWindowEx 失败，Win32 错误码 {Marshal.GetLastWin32Error()}。");
        }

        return true;
    }

    private IntPtr LoadTrayIcon(string iconPath)
    {
        if (!string.IsNullOrWhiteSpace(iconPath) && File.Exists(iconPath))
        {
            var loaded = LoadImageW(
                IntPtr.Zero,
                iconPath,
                IMAGE_ICON,
                0,
                0,
                LR_LOADFROMFILE | LR_DEFAULTSIZE);
            if (loaded != IntPtr.Zero)
            {
                _ownsIcon = true;
                return loaded;
            }
        }

        _ownsIcon = false;
        return LoadIconW(IntPtr.Zero, (IntPtr)IDI_APPLICATION);
    }

    private NOTIFYICONDATAW CreateData(uint flags)
    {
        return new NOTIFYICONDATAW
        {
            cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATAW>(),
            hWnd = _hostWindow,
            uID = TrayIconId,
            uFlags = flags,
            uCallbackMessage = TrayCallbackMessage,
            hIcon = _icon,
            szTip = _tooltip,
            szInfo = string.Empty,
            szInfoTitle = string.Empty,
            guidItem = Guid.Empty
        };
    }

    private void ShowContextMenu(IntPtr hWnd)
    {
        var menu = CreatePopupMenu();
        if (menu == IntPtr.Zero)
        {
            return;
        }

        try
        {
            AppendMenuW(menu, MF_STRING | MF_DEFAULT, (UIntPtr)(uint)ID_SHOW, "打开主界面");
            AppendMenuW(menu, MF_SEPARATOR, UIntPtr.Zero, null);
            AppendMenuW(menu, MF_STRING, (UIntPtr)(uint)ID_EXIT, "退出");

            GetCursorPos(out var point);
            SetForegroundWindow(hWnd);
            var command = TrackPopupMenu(
                menu,
                TPM_RETURNCMD | TPM_RIGHTBUTTON,
                point.X,
                point.Y,
                0,
                hWnd,
                IntPtr.Zero);
            PostMessageW(hWnd, WM_NULL, IntPtr.Zero, IntPtr.Zero);

            if (command == ID_SHOW)
            {
                _onOpen();
            }
            else if (command == ID_EXIT)
            {
                _onExit();
            }
        }
        finally
        {
            DestroyMenu(menu);
        }
    }

    private void RestoreIcon()
    {
        if (_disposed || _hostWindow == IntPtr.Zero)
        {
            return;
        }

        var data = CreateData(NIF_MESSAGE | NIF_ICON | NIF_TIP);
        if (!Shell_NotifyIconW(NIM_ADD, ref data))
        {
            Shell_NotifyIconW(NIM_MODIFY, ref data);
        }
    }

    private static IntPtr WindowProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam)
    {
        var service = _current;
        if (service is not null && !service._disposed)
        {
            if (msg != 0 && msg == service._taskbarCreatedMessage)
            {
                service.RestoreIcon();
                return IntPtr.Zero;
            }

            if (msg == TrayCallbackMessage)
            {
                var mouseMessage = unchecked((int)lParam.ToInt64());
                if (mouseMessage == WM_LBUTTONDBLCLK)
                {
                    service._onOpen();
                    return IntPtr.Zero;
                }

                if (mouseMessage == WM_RBUTTONUP || mouseMessage == WM_CONTEXTMENU)
                {
                    service.ShowContextMenu(hWnd);
                    return IntPtr.Zero;
                }
            }
        }

        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }

    private delegate IntPtr WindowProcDelegate(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WNDCLASSEXW
    {
        public uint cbSize;
        public uint style;
        public IntPtr lpfnWndProc;
        public int cbClsExtra;
        public int cbWndExtra;
        public IntPtr hInstance;
        public IntPtr hIcon;
        public IntPtr hCursor;
        public IntPtr hbrBackground;
        public string? lpszMenuName;
        public string lpszClassName;
        public IntPtr hIconSm;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NOTIFYICONDATAW
    {
        public uint cbSize;
        public IntPtr hWnd;
        public uint uID;
        public uint uFlags;
        public uint uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szTip;
        public uint dwState;
        public uint dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szInfo;
        public uint uTimeoutOrVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string szInfoTitle;
        public uint dwInfoFlags;
        public Guid guidItem;
        public IntPtr hBalloonIcon;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT
    {
        public int X;
        public int Y;
    }

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern ushort RegisterClassExW(ref WNDCLASSEXW lpwcx);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateWindowExW(
        uint dwExStyle,
        string lpClassName,
        string lpWindowName,
        uint dwStyle,
        int x,
        int y,
        int nWidth,
        int nHeight,
        IntPtr hWndParent,
        IntPtr hMenu,
        IntPtr hInstance,
        IntPtr lpParam);

    [DllImport("user32.dll")]
    private static extern IntPtr DefWindowProcW(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyWindow(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool UnregisterClassW(string lpClassName, IntPtr hInstance);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandleW(string? lpModuleName);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Shell_NotifyIconW(uint dwMessage, ref NOTIFYICONDATAW lpData);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr LoadImageW(IntPtr hInst, string name, uint type, int cx, int cy, uint fuLoad);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr LoadIconW(IntPtr hInstance, IntPtr lpIconName);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr hIcon);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern IntPtr CreatePopupMenu();

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool AppendMenuW(IntPtr hMenu, uint uFlags, UIntPtr uIDNewItem, string? lpNewItem);

    [DllImport("user32.dll")]
    private static extern bool DestroyMenu(IntPtr hMenu);

    [DllImport("user32.dll")]
    private static extern int TrackPopupMenu(IntPtr hMenu, uint uFlags, int x, int y, int nReserved, IntPtr hWnd, IntPtr prcRect);

    [DllImport("user32.dll")]
    private static extern bool GetCursorPos(out POINT lpPoint);

    [DllImport("user32.dll")]
    private static extern bool PostMessageW(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern uint RegisterWindowMessageW(string lpString);
}
