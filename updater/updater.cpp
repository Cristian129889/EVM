// ============================================================================
//  Actualizador de EVM
//  ------------------------------------------------------------------------
//  Sustituye al descargador interno de BGT, que no soporta HTTPS.
//
//  Hace tres cosas:
//    1. Descarga manifest.txt por HTTPS (WinHTTP, TLS nativo de Windows).
//    2. Si hay version mas nueva, baja cada archivo indicado.
//    3. Verifica tamano y SHA-256 ANTES de reemplazar nada.
//
//  Solo usa DLLs del sistema: kernel32, winhttp, bcrypt, comctl32.
//  Compilar:  build.bat   (o ver la cabecera de ese archivo)
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <commctrl.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <functional>
#include <cstdio>
#include <cstdint>
#include <cstdlib>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shell32.lib")

// ---------------------------------------------------------------------------
//  Constantes
// ---------------------------------------------------------------------------
static const wchar_t* APP_NAME   = L"Actualizador de EVM";
static const wchar_t* MANIFEST   = L"manifest.txt";
static const wchar_t* USER_AGENT = L"EVM-Updater/1.0";

// Mensajes internos de la interfaz
#define WM_UPD_STATUS   (WM_APP + 1)   // wParam = wchar_t*  (texto de estado)
#define WM_UPD_PROGRESS (WM_APP + 2)   // wParam = porcentaje 0..100
#define WM_UPD_DETAIL   (WM_APP + 3)   // wParam = wchar_t*  (detalle)
#define WM_UPD_FINISH   (WM_APP + 4)   // wParam = bool exito, lParam = wchar_t*

// ---------------------------------------------------------------------------
//  Conversion UTF-8 <-> UTF-16
// ---------------------------------------------------------------------------
static std::wstring Utf8ToWide(const std::string& s)
{
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), NULL, 0);
    std::wstring w;
    w.resize(n);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

static std::string WideToUtf8(const std::wstring& w)
{
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), NULL, 0, NULL, NULL);
    std::string s;
    s.resize(n);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, NULL, NULL);
    return s;
}

static std::string Trim(const std::string& s)
{
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

static std::string ToLowerAscii(std::string s)
{
    for (char& c : s) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    return s;
}

// ---------------------------------------------------------------------------
//  Comparacion de versiones  (1.2 > 1.10 -> false, 1.10 > 1.2 -> true)
//  Devuelve: >0 si a es mas nueva, <0 si b es mas nueva, 0 si son iguales
// ---------------------------------------------------------------------------
static int CompareVersions(const std::string& a, const std::string& b)
{
    size_t ia = 0, ib = 0;
    while (ia < a.size() || ib < b.size())
    {
        long na = 0, nb = 0;
        while (ia < a.size() && a[ia] >= '0' && a[ia] <= '9')
            na = na * 10 + (a[ia++] - '0');
        while (ib < b.size() && b[ib] >= '0' && b[ib] <= '9')
            nb = nb * 10 + (b[ib++] - '0');
        if (na != nb) return na < nb ? -1 : 1;

        // saltar el separador
        while (ia < a.size() && (a[ia] < '0' || a[ia] > '9')) ia++;
        while (ib < b.size() && (b[ib] < '0' || b[ib] > '9')) ib++;
    }
    return 0;
}

// ---------------------------------------------------------------------------
//  SHA-256 mediante BCrypt (cryptoAPI de Windows, sin librerias extra)
// ---------------------------------------------------------------------------
class Sha256
{
public:
    Sha256()
    {
        m_alg = NULL; m_hash = NULL;
        if (BCryptOpenAlgorithmProvider(&m_alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0)
            return;

        DWORD len = 0, got = 0;
        if (BCryptGetProperty(m_alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&len, sizeof(len), &got, 0) != 0)
            return;

        m_obj.assign(len, 0);
        BCryptCreateHash(m_alg, &m_hash, m_obj.data(), len, NULL, 0, 0);
    }

    ~Sha256()
    {
        if (m_hash) BCryptDestroyHash(m_hash);
        if (m_alg)  BCryptCloseAlgorithmProvider(m_alg, 0);
    }

    bool ok() const { return m_hash != NULL; }

    void update(const unsigned char* data, size_t n)
    {
        if (m_hash && n) BCryptHashData(m_hash, (PUCHAR)data, (ULONG)n, 0);
    }

    std::string hex()
    {
        if (!m_hash) return "";
        unsigned char digest[32] = { 0 };
        BCryptFinishHash(m_hash, digest, sizeof(digest), 0);

        char buf[65];
        for (int i = 0; i < 32; i++) sprintf_s(buf + i * 2, 3, "%02x", digest[i]);
        buf[64] = 0;
        return std::string(buf);
    }

private:
    BCRYPT_ALG_HANDLE  m_alg;
    BCRYPT_HASH_HANDLE m_hash;
    std::vector<unsigned char> m_obj;
};

// ---------------------------------------------------------------------------
//  HTTP por WinHTTP
// ---------------------------------------------------------------------------
struct UrlParts
{
    std::wstring host, path;
    bool secure;
    int port;
};

static bool SplitUrl(const std::wstring& url, UrlParts& out)
{
    URL_COMPONENTS uc;
    ZeroMemory(&uc, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256] = { 0 }, path[1024] = { 0 };
    uc.lpszHostName      = host;  uc.dwHostNameLength      = 256;
    uc.lpszUrlPath       = path;  uc.dwUrlPathLength       = 1024;

    if (!WinHttpCrackUrl(url.c_str(), (DWORD)url.size(), 0, &uc)) return false;

    out.host.assign(host, uc.dwHostNameLength);
    out.path.assign(path, uc.dwUrlPathLength);
    out.secure = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    out.port   = uc.nPort;
    if (out.path.empty()) out.path = L"/";
    return true;
}

static std::wstring JoinUrl(const std::wstring& base, const std::wstring& file)
{
    std::wstring u = base;
    while (!u.empty() && (u[u.size() - 1] == L'/' || u[u.size() - 1] == L'\\'))
        u.erase(u.size() - 1);
    u += L"/";
    u += file;
    return u;
}

class Http
{
public:
    Http() : m_session(NULL) {}

    ~Http() { close(); }

    bool open()
    {
        m_session = WinHttpOpen(USER_AGENT,
                                WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                WINHTTP_NO_PROXY_NAME,
                                WINHTTP_NO_PROXY_BYPASS, 0);
        if (!m_session) return false;

        // Solo TLS 1.2 y 1.3
        DWORD flags = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
        WinHttpSetOption(m_session, WINHTTP_OPTION_SECURE_PROTOCOLS, &flags, sizeof(flags));
        return true;
    }

    void close()
    {
        if (m_conn) { WinHttpCloseHandle(m_conn); m_conn = NULL; }
        if (m_session) { WinHttpCloseHandle(m_session); m_session = NULL; }
    }

    // Descarga a memoria. Devuelve false y rellena error si falla.
    bool get(const std::wstring& url, std::string& out, std::wstring& error)
    {
        out.clear();
        HINTERNET h = request(url, error);
        if (!h) return false;

        DWORD code = 0, sz = sizeof(code);
        WinHttpQueryHeaders(h, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &code, &sz, WINHTTP_NO_HEADER_INDEX);
        if (code != 200)
        {
            error = L"El servidor respondio codigo " + std::to_wstring(code);
            WinHttpCloseHandle(h);
            return false;
        }

        for (;;)
        {
            DWORD avail = 0;
            if (!WinHttpQueryDataAvailable(h, &avail) || avail == 0) break;
            std::vector<char> buf(avail);
            DWORD got = 0;
            if (!WinHttpReadData(h, buf.data(), avail, &got) || got == 0) break;
            out.append(buf.data(), got);
        }

        DWORD err = GetLastError();
        WinHttpCloseHandle(h);
        if (err != ERROR_SUCCESS && !out.empty())
        {
            // Some servers close without a clean EOS; data is still usable.
        }
        return true;
    }

    // Descarga a un archivo, informando progreso.
    // fn(done,total) se llama durante la descarga.
    bool download(const std::wstring& url, const std::wstring& dest,
                  Sha256* hash, long long knownSize,
                  const std::function<void(long long, long long)>& fn,
                  std::wstring& error)
    {
        HINTERNET h = request(url, error);
        if (!h) return false;

        DWORD code = 0, sz = sizeof(code);
        WinHttpQueryHeaders(h, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &code, &sz, WINHTTP_NO_HEADER_INDEX);
        if (code != 200)
        {
            error = L"El servidor respondio codigo " + std::to_wstring(code) +
                    L" a:\n" + url;
            WinHttpCloseHandle(h);
            return false;
        }

        HANDLE f = CreateFileW(dest.c_str(), GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (f == INVALID_HANDLE_VALUE)
        {
            error = L"No se pudo crear " + dest;
            WinHttpCloseHandle(h);
            return false;
        }

        long long total = 0;
        DWORD len = 0;
        WinHttpQueryHeaders(h, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &len, &sz, WINHTTP_NO_HEADER_INDEX);
        total = (long long)len;
        if (total <= 0) total = knownSize;

        long long done = 0;
        bool okflag = true;

        for (;;)
        {
            DWORD avail = 0;
            if (!WinHttpQueryDataAvailable(h, &avail) || avail == 0) break;

            std::vector<char> buf(avail);
            DWORD got = 0;
            if (!WinHttpReadData(h, buf.data(), avail, &got) || got == 0) break;

            DWORD wr = 0;
            WriteFile(f, buf.data(), got, &wr, NULL);
            if (wr != got) { okflag = false; error = L"Fallo al escribir en disco"; break; }

            if (hash) hash->update((const unsigned char*)buf.data(), got);
            done += got;
            if (fn) fn(done, total);
        }

        CloseHandle(f);
        DWORD err = GetLastError();
        WinHttpCloseHandle(h);
        if (!okflag) return false;
        if (err != ERROR_SUCCESS && done == 0)
        {
            error = L"La descarga se corto";
            return false;
        }
        return true;
    }

private:
    HINTERNET request(const std::wstring& url, std::wstring& error)
    {
        UrlParts p;
        if (!SplitUrl(url, p))
        {
            error = L"URL invalida: " + url;
            return NULL;
        }

        // Una sola conexion por host, reutilizada entre peticiones.
        if (m_conn && m_connHost != p.host)
        {
            WinHttpCloseHandle(m_conn);
            m_conn = NULL;
        }
        if (!m_conn)
        {
            m_conn = WinHttpConnect(m_session, p.host.c_str(), (INTERNET_PORT)p.port, 0);
            if (!m_conn)
            {
                error = L"No se pudo conectar con " + p.host;
                return NULL;
            }
            m_connHost = p.host;
        }

        HINTERNET req = WinHttpOpenRequest(m_conn, L"GET", p.path.c_str(), NULL,
                                           WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES,
                                           p.secure ? WINHTTP_FLAG_SECURE : 0);
        if (!req)
        {
            error = L"No se pudo abrir la peticion";
            return NULL;
        }

        DWORD redirect = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
        WinHttpSetOption(req, WINHTTP_OPTION_REDIRECT_POLICY, &redirect, sizeof(redirect));

        // Sin "Accept" algunos servidores (GitHub incluido) responden 406.
        static const wchar_t* HDRS = L"Accept: */*\r\n";
        if (!WinHttpSendRequest(req, HDRS, (DWORD)-1L,
                                WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
            !WinHttpReceiveResponse(req, NULL))
        {
            DWORD e = GetLastError();
            WinHttpCloseHandle(req);
            error = (e == ERROR_WINHTTP_SECURE_FAILURE)
                        ? L"Fallo de seguridad/TLS (certificado)"
                        : L"Fallo de conexion de red";
            return NULL;
        }

        return req;
    }

    HINTERNET m_session;
    HINTERNET m_conn = NULL;
    std::wstring m_connHost;
};

// ---------------------------------------------------------------------------
//  Manifiesto
// ---------------------------------------------------------------------------
struct FileEntry
{
    std::string dest;    // ruta relativa de destino, con /
    std::string asset;   // nombre del asset en el release
    std::string sha256;  // hash en minusculas, 64 hex
    long long   size;
};

struct Manifest
{
    std::string version;
    std::string notes;
    std::vector<FileEntry> files;
};

static bool ParseManifest(const std::string& text, Manifest& m, std::wstring& error)
{
    size_t pos = 0;
    while (pos <= text.size())
    {
        size_t eol = text.find('\n', pos);
        if (eol == std::string::npos) eol = text.size();
        std::string line = Trim(text.substr(pos, eol - pos));
        pos = eol + 1;

        if (line.empty() || line[0] == '#') continue;

        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = ToLowerAscii(Trim(line.substr(0, eq)));
        std::string val = Trim(line.substr(eq + 1));

        if (key == "version")
        {
            m.version = val;
        }
        else if (key == "notes")
        {
            m.notes = val;
        }
        else if (key == "file")
        {
            // file=<ruta_destino>|<asset>|<sha256>|<tamano>
            std::vector<std::string> f;
            size_t s = 0;
            for (int i = 0; i < 4; i++)
            {
                size_t bar = val.find('|', s);
                f.push_back(val.substr(s, bar - s));
                if (bar == std::string::npos) break;
                s = bar + 1;
            }
            if (f.size() < 4)
            {
                error = L"Linea 'file' incompleta en el manifiesto";
                return false;
            }
            FileEntry fe;
            fe.dest  = f[0];
            fe.asset = f[1];
            fe.sha256 = ToLowerAscii(f[2]);
            fe.size  = atoll(f[3].c_str());
            if (fe.dest.empty() || fe.sha256.size() != 64)
            {
                error = L"Entrada 'file' invalida en el manifiesto";
                return false;
            }
            m.files.push_back(fe);
        }
    }

    if (m.version.empty())
    {
        error = L"El manifiesto no tiene 'version='";
        return false;
    }
    if (m.files.empty())
    {
        error = L"El manifiesto no lista ningun archivo";
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
//  Utilidades de disco
// ---------------------------------------------------------------------------
static std::wstring DirName(const std::wstring& path)
{
    size_t p = path.find_last_of(L"\\/");
    if (p == std::string::npos) return L".";
    return path.substr(0, p);
}

static bool MakeDirs(const std::wstring& base, const std::string& rel)
{
    // Crear solo los directorios del caminho, nunca el archivo final.
    size_t last = rel.find_last_of('/');
    if (last == std::string::npos)
    {
        // El archivo va en la raiz: basta con que exista la carpeta base.
        DWORD a = GetFileAttributesW(base.c_str());
        return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) != 0;
    }

    std::wstring full = base;
    size_t start = 0;
    for (;;)
    {
        size_t slash = rel.find('/', start);
        if (slash == std::string::npos || slash >= last) break;

        std::string part = rel.substr(start, slash - start);
        if (!part.empty())
        {
            full += L"\\";
            full += Utf8ToWide(part);
            CreateDirectoryW(full.c_str(), NULL);
        }
        start = slash + 1;
    }

    DWORD a = GetFileAttributesW(full.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

// ---------------------------------------------------------------------------
//  Espera a que el juego se cierre
//  En Windows no se puede sobrescribir un .exe en ejecucion.
// ---------------------------------------------------------------------------
static bool CanWrite(const std::wstring& path)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    CloseHandle(h);
    return true;
}

static bool WaitForGameToClose(const std::wstring& exe, int seconds,
                               const std::function<void(int)>& onWait)
{
    if (CanWrite(exe)) return true;
    for (int i = seconds; i > 0; i--)
    {
        if (onWait) onWait(i);
        Sleep(1000);
        if (CanWrite(exe)) return true;
    }
    return CanWrite(exe);
}

// ---------------------------------------------------------------------------
//  Formato de tamano
// ---------------------------------------------------------------------------
static std::wstring HumanSize(long long b)
{
    wchar_t buf[64];
    if (b >= 1048576)      swprintf_s(buf, L"%.1f MB", b / 1048576.0);
    else if (b >= 1024)    swprintf_s(buf, L"%.0f KB", b / 1024.0);
    else                   swprintf_s(buf, L"%lld bytes", b);
    return buf;
}

// ---------------------------------------------------------------------------
//  Interfaz grafica
// ---------------------------------------------------------------------------
static HWND g_hwnd = NULL;
static HWND g_bar  = NULL;
static HWND g_lblStatus = NULL;
static HWND g_lblDetail = NULL;
static HWND g_btn   = NULL;
static bool g_console = false;
static int  g_exitCode = 0;

// En modo --console puede que no haya consola propia (lanzado desde otro
// proceso). Si no hay, se engancha a la del padre.
static void EnsureConsole()
{
    if (GetStdHandle(STD_OUTPUT_HANDLE) != NULL) return;
    if (AttachConsole(ATTACH_PARENT_PROCESS))
    {
        FILE* out = NULL;
        FILE* in  = NULL;
        freopen_s(&out, "CONOUT$", "w", stdout);
        freopen_s(&in,  "CONIN$",  "r", stdin);
    }
}

static void Say(const std::wstring& t)
{
    if (g_console) { printf("%s\n", WideToUtf8(t).c_str()); fflush(stdout); return; }
    if (!g_hwnd) return;
    std::wstring* copy = new std::wstring(t);
    PostMessageW(g_hwnd, WM_UPD_STATUS, 0, (LPARAM)copy);
}

static void Detail(const std::wstring& t)
{
    if (g_console) { printf("  %s\n", WideToUtf8(t).c_str()); fflush(stdout); return; }
    if (!g_hwnd) return;
    std::wstring* copy = new std::wstring(t);
    PostMessageW(g_hwnd, WM_UPD_DETAIL, 0, (LPARAM)copy);
}

static void Progress(int pct)
{
    if (g_console) return;
    if (g_hwnd) PostMessageW(g_hwnd, WM_UPD_PROGRESS, (WPARAM)pct, 0);
}

static void Finish(bool ok, const std::wstring& msg)
{
    g_exitCode = ok ? 0 : 1;
    if (g_console)
    {
        printf("%s\n[%s]\n", WideToUtf8(msg).c_str(), ok ? "OK" : "ERROR");
        fflush(stdout);
        return;
    }
    if (!g_hwnd) return;
    std::wstring* copy = new std::wstring(msg);
    PostMessageW(g_hwnd, WM_UPD_FINISH, (WPARAM)(ok ? 1 : 0), (LPARAM)copy);
}

// ---------------------------------------------------------------------------
//  Hilo de trabajo: toda la logica de red y disco
// ---------------------------------------------------------------------------
struct Options
{
    std::wstring baseUrl;
    std::wstring current;
    std::wstring gameDir;
    std::wstring exeName = L"client.exe";
    bool launch = true;
};

static std::wstring g_exePath;
static Options      g_opt;

static void RunUpdate()
{
    Say(L"Conectando con el servidor de actualizaciones...");

    Http http;
    if (!http.open())
    {
        Finish(false, L"No se pudo iniciar la conexion de red.");
        return;
    }

    // --- 1. manifiesto -----------------------------------------------------
    std::string text;
    std::wstring err;
    if (!http.get(JoinUrl(g_opt.baseUrl, MANIFEST), text, err))
    {
        Finish(false, L"No se pudo descargar el manifiesto.\n" + err +
                      L"\n\nComprueba tu conexion a internet.");
        return;
    }

    Manifest man;
    if (!ParseManifest(text, man, err))
    {
        Finish(false, L"El manifiesto esta danado.\n" + err);
        return;
    }

    // --- 2. comparar versiones --------------------------------------------
    int cmp = CompareVersions(man.version, WideToUtf8(g_opt.current));
    if (cmp == 0)
    {
        Finish(true, L"Ya tienes la ultima version (" + Utf8ToWide(man.version) + L").");
        return;
    }
    if (cmp < 0)
    {
        Finish(true, L"Tu version (" + g_opt.current +
                     L") es mas nueva que la publicada.");
        return;
    }

    Say(L"Encontrada version nueva: " + Utf8ToWide(man.version));
    if (!man.notes.empty())
        Detail(L"Nota: " + Utf8ToWide(man.notes));

    // --- 3. esperar a que el juego se cierre ------------------------------
    std::wstring gameExe = g_opt.gameDir + L"\\" + g_opt.exeName;
    if (!CanWrite(gameExe))
    {
        Say(L"Cierra el juego para poder actualizar...");
        if (!WaitForGameToClose(gameExe, 60,
            [](int s) { Detail(L"El juego sigue abierto. Reintentando en " + std::to_wstring(s) + L" s..."); }))
        {
            Finish(false, L"El juego sigue abierto. Cierralo y ejecuta el actualizador otra vez.");
            return;
        }
    }

    // --- 4. descargar y verificar -----------------------------------------
    const int nf = (int)man.files.size();
    std::vector<std::wstring> temps(nf);

    // Si algo falla, no debe quedar ni un solo .parte por ahi.
    auto fail = [&temps](const std::wstring& msg)
    {
        for (auto& t : temps)
            if (!t.empty()) DeleteFileW(t.c_str());
        Finish(false, msg);
    };

    for (int i = 0; i < nf; i++)
    {
        const FileEntry& fe = man.files[i];

        std::wstring dest = g_opt.gameDir + L"\\" + Utf8ToWide(fe.dest);
        if (!MakeDirs(g_opt.gameDir, fe.dest))
        {
            fail(L"No se pudo crear la carpeta para " + Utf8ToWide(fe.dest));
            return;
        }

        std::wstring tmp = dest + L".parte";
        temps[i] = tmp;

        Detail(L"Descargando " + Utf8ToWide(fe.dest) + L" (" + HumanSize(fe.size) + L")");

        Sha256 h;
        if (!h.ok())
        {
            fail(L"No se pudo inicializar SHA-256.");
            return;
        }

        const int base = i * 100 / nf;
        const int span = 100 / nf;

        bool okd = http.download(JoinUrl(g_opt.baseUrl, Utf8ToWide(fe.asset)), tmp,
                                 &h, fe.size,
            [base, span](long long done, long long total) {
                if (total > 0)
                {
                    int pct = base + (int)((done * span) / total);
                    if (pct > 100) pct = 100;
                    Progress(pct);
                }
            }, err);

        if (!okd)
        {
            DeleteFileW(tmp.c_str());
            fail( L"Fallo la descarga de " + Utf8ToWide(fe.dest) + L".\n" + err);
            return;
        }

        // verificar tamano
        WIN32_FIND_DATAW fd;
        if (GetFileAttributesExW(tmp.c_str(), GetFileExInfoStandard, &fd))
        {
            long long got = ((long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            if (fe.size > 0 && got != fe.size)
            {
                DeleteFileW(tmp.c_str());
                fail( L"Archivo danado: " + Utf8ToWide(fe.dest) +
                              L"\nTamano esperado " + HumanSize(fe.size) +
                              L", recibido " + HumanSize(got) + L".");
                return;
            }
        }

        // verificar SHA-256
        std::string got = h.hex();
        if (ToLowerAscii(fe.sha256) != got)
        {
            DeleteFileW(tmp.c_str());
            fail( L"Archivo danado: " + Utf8ToWide(fe.dest) +
                          L"\nLa suma SHA-256 no coincide.\nSe descargo a medias.");
            return;
        }
    }

    // --- 5. reemplazar (todo verificado antes de tocar nada) -------------
    Say(L"Verificacion correcta. Instalando...");
    for (int i = 0; i < nf; i++)
    {
        const FileEntry& fe = man.files[i];
        std::wstring dest = g_opt.gameDir + L"\\" + Utf8ToWide(fe.dest);

        if (!MoveFileExW(temps[i].c_str(), dest.c_str(),
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            Finish(false, L"No se pudo reemplazar " + Utf8ToWide(fe.dest) +
                          L".\nCierra el juego y vuelve a intentarlo.");
            return;
        }
    }
    Progress(100);

    // --- 6. relanzar -------------------------------------------------------
    if (g_opt.launch)
    {
        std::wstring gameExe2 = g_opt.gameDir + L"\\" + g_opt.exeName;
        if (GetFileAttributesW(gameExe2.c_str()) != INVALID_FILE_ATTRIBUTES)
        {
            Say(L"Iniciando el juego...");
            Sleep(600);
            STARTUPINFOW si;
            PROCESS_INFORMATION pi;
            ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
            CreateProcessW(gameExe2.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
            if (pi.hThread) CloseHandle(pi.hThread);
            if (pi.hProcess) CloseHandle(pi.hProcess);
        }
    }

    Finish(true, L"Actualizado a la version " + Utf8ToWide(man.version) + L".\nAbre el juego.");
}

static DWORD WINAPI WorkerProc(LPVOID)
{
    RunUpdate();
    if (!g_console && g_hwnd) PostMessageW(g_hwnd, WM_CLOSE, 0, 0);
    return 0;
}

// ---------------------------------------------------------------------------
//  Ventana
// ---------------------------------------------------------------------------
static void CreateControls(HWND h)
{
    HFONT f = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

    g_lblStatus = CreateWindowExW(0, L"STATIC", L"Iniciando...",
        WS_CHILD | WS_VISIBLE, 20, 20, 420, 20, h, NULL, NULL, NULL);
    g_bar  = CreateWindowExW(0, PROGRESS_CLASSW, NULL,
        WS_CHILD | WS_VISIBLE, 20, 50, 420, 22, h, NULL, NULL, NULL);
    g_lblDetail = CreateWindowExW(0, L"STATIC", L"",
        WS_CHILD | WS_VISIBLE, 20, 80, 420, 34, h, NULL, NULL, NULL);
    g_btn = CreateWindowExW(0, L"BUTTON", L"Cerrar",
        WS_CHILD | WS_VISIBLE | WS_DISABLED, 170, 130, 120, 30, h, (HMENU)1, NULL, NULL);

    SendMessageW(g_lblStatus, WM_SETFONT, (WPARAM)f, TRUE);
    SendMessageW(g_lblDetail, WM_SETFONT, (WPARAM)f, TRUE);
    SendMessageW(g_btn,       WM_SETFONT, (WPARAM)f, TRUE);
    SendMessageW(g_bar, PBM_SETRANGE32, 0, 100);
    SendMessageW(g_bar, PBM_SETPOS, 0, 0);
}

static LRESULT CALLBACK WndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_CREATE:
        CreateControls(h);
        return 0;

    case WM_COMMAND:
        if (LOWORD(wp) == 1 && HIWORD(wp) == BN_CLICKED)
        {
            if (g_btn) EnableWindow(g_btn, FALSE);
            PostMessageW(h, WM_CLOSE, 0, 0);
            return 0;
        }
        break;

    case WM_UPD_STATUS:
    {
        std::wstring* t = (std::wstring*)lp;
        if (g_lblStatus) SetWindowTextW(g_lblStatus, t->c_str());
        delete t;
        return 0;
    }

    case WM_UPD_DETAIL:
    {
        std::wstring* t = (std::wstring*)lp;
        if (g_lblDetail) SetWindowTextW(g_lblDetail, t->c_str());
        delete t;
        return 0;
    }

    case WM_UPD_PROGRESS:
        if (g_bar) SendMessageW(g_bar, PBM_SETPOS, (WPARAM)wp, 0);
        return 0;

    case WM_UPD_FINISH:
    {
        std::wstring* t = (std::wstring*)lp;
        if (g_lblStatus) SetWindowTextW(g_lblStatus, t->c_str());
        if (g_lblDetail) SetWindowTextW(g_lblDetail, L"");
        if (g_bar) SendMessageW(g_bar, PBM_SETPOS, 100, 0);
        if (g_btn) EnableWindow(g_btn, TRUE);
        delete t;
        return 0;
    }

    case WM_CLOSE:
        DestroyWindow(h);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(h, msg, wp, lp);
}

static void PrintUsage()
{
    printf("Actualizador de EVM\n");
    printf("  --url <url>    URL base del release (obligatorio)\n");
    printf("  --ver <x.y>    Version actual instalada\n");
    printf("  --dir <ruta>   Carpeta de instalacion (por defecto, la del .exe)\n");
    printf("  --exe <n>      Ejecutable a relanzar (por defecto client.exe)\n");
    printf("  --no-launch    No iniciar el juego al terminar\n");
    printf("  --console      Salida por consola en vez de ventana\n");
    printf("  --help         Esta ayuda\n");
}

// ---------------------------------------------------------------------------
//  Entrada
// ---------------------------------------------------------------------------
int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, LPWSTR, int)
{
    // En modo consola hay que adjuntar stdout para poder escribir.
    g_console = false;
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return 1;

    std::wstring baseUrl, current, dir, exeName = L"client.exe";
    bool launch = true, wantConsole = false;

    for (int i = 1; i < argc; i++)
    {
        std::wstring a = argv[i];
        if (a == L"--url"       && i + 1 < argc) baseUrl  = argv[++i];
        else if (a == L"--ver"   && i + 1 < argc) current = argv[++i];
        else if (a == L"--dir"   && i + 1 < argc) dir     = argv[++i];
        else if (a == L"--exe"   && i + 1 < argc) exeName = argv[++i];
        else if (a == L"--no-launch") launch = false;
        else if (a == L"--console")   wantConsole = true;
        else if (a == L"--help" || a == L"-h" || a == L"/?")
        {
            EnsureConsole();
            PrintUsage();
            LocalFree(argv);
            return 0;
        }
    }
    LocalFree(argv);

    if (baseUrl.empty() || current.empty())
    {
        EnsureConsole();
        printf("Falta --url o --ver.\n\n");
        PrintUsage();
        return 2;
    }

    // Carpeta por defecto: la del propio actualizador (= carpeta del juego).
    std::wstring self;
    {
        wchar_t buf[MAX_PATH];
        DWORD n = GetModuleFileNameW(NULL, buf, MAX_PATH);
        self.assign(buf, n);
    }
    g_exePath = self;

    g_opt.baseUrl  = baseUrl;
    g_opt.current  = current;
    g_opt.gameDir  = dir.empty() ? DirName(self) : dir;
    g_opt.exeName  = exeName;
    g_opt.launch   = launch;

    // ---- modo consola (para pruebas y depuracion) ----
    if (wantConsole)
    {
        EnsureConsole();
        g_console = true;
        RunUpdate();
        return g_exitCode;
    }

    // ---- modo ventana ----
    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc);
    icc.dwICC  = ICC_BAR_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    WNDCLASSEXW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = inst;
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"EVMPUpdater";
    if (!RegisterClassExW(&wc))
    {
        EnsureConsole();
        printf("No se pudo registrar la ventana.\n");
        return 1;
    }

    g_hwnd = CreateWindowExW(0, L"EVMPUpdater", APP_NAME,
                             WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                             CW_USEDEFAULT, CW_USEDEFAULT, 470, 210,
                             NULL, NULL, inst, NULL);
    if (!g_hwnd) return 1;

    ShowWindow(g_hwnd, SW_SHOWNORMAL);
    UpdateWindow(g_hwnd);

    CreateThread(NULL, 0, WorkerProc, NULL, 0, NULL);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return g_exitCode;
}
