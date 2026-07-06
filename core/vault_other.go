//go:build !windows

// На не-Windows системах привязка к машине (DPAPI) недоступна: dpapiProtect
// и dpapiUnprotect остаются nil, что SealVault/OpenVault трактуют как явную
// ошибку "недоступно на этой ОС" при попытке machineBind.
package core
