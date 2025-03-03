
class WinError {
public:
	DWORD code = 0;
	LPWSTR message = NULL;
	~WinError();
	WinError();
	WinError(const WinError& source) = delete;
	WinError& operator=(const WinError& source) = delete;
};
