// Package confdirguard — место для структурного сторожа A4в: имя каталога
// клиентских конфигов не должно снова появиться в cmd/ строковым литералом.
// Сам сторож живёт в confdirguard_test.go; продуктового кода в пакете нет —
// как и в internal/permguard.
package confdirguard
