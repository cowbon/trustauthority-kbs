/*
 *   Copyright (c) 2024-2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"context"
	"encoding/base64"
	"intel/kbs/v1/model"
	"net/http"
	"testing"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	itaConnector "github.com/intel/trustauthority-client/go-connector"
	"github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var (
	publicKey = "AQABAEWpyf19e2eARCPq/l07CvkPGIoJK+48tDtv5sB5WswB2OY63qSxb+DxOrZ/b54BNF6xeS/+s7W81z+5RKQwmewIageZZByWHp0xs6eOnhoGMpdDEHFhIfp9an5e4wP8tnoaYyzeD66J5Wgd3gX+sBv6GL1BBRq4M1bNVslXcz4w3s4xWWO2CLfgSpI1jAToEhxLxta+e5Istn4v2hXsuEmkeSL5NHrcfy7AmPhFISUoyyJZ9121jEkW/yl/oGbJegfeWwD316Af69gawFCO29xjupnfQa7XCR+YrB2XTIqDqHAbo1fQabrdG3HlyIivyayFYz6moztv0VMnoAfUFzZ70ZvcefcI2HACo2qIJmathyoisuwH3aZ0Ojcg53rSBsTK9QN4jzyYkIg0Dl0prjzrIIyTxerDf+/R/YDTNy9KC6OCluZe0xLmYwFfOcPMr6taWVEPDM7K8Rmub5Hw02mCPXNhNjOTrPxM5wqrLbX5xJ5fJs33wlv5e+XVi2agjQ=="
	nonce     = &itaConnector.VerifierNonce{}
	sgxToken  = "eyJhbGciOiJQUzM4NCIsImprdSI6Imh0dHBzOi8vYW1iZXItcG9jLXVzZXIxLnByb2plY3QtYW1iZXItc21hcy5jb20vY2VydHMiLCJraWQiOiJkN2VjN2RlZjY3NzVhMjdiZTRkNGUzODY1NGZhMWNlOGM1ZTI5MjI2YzgzZTIwNTQwMGU0NDExNzI4YjA2YTQ2ZDY5MDU5ZWU2NGM5NmY0MjE0NTU2YWNmYmQzYjcwNDYiLCJ0eXAiOiJKV1QifQ.eyJzZ3hfbXJlbmNsYXZlIjoiODNmNGU4MTk4NjFhZGVmNmZmYjJhNDg2NWVmZWE5MzM3YjkxZWQzMGZhMzM0OTFiMTdmMGQ1ZDllODIwNDQxMCIsInNneF9tcnNpZ25lciI6IjgzZDcxOWU3N2RlYWNhMTQ3MGY2YmFmNjJhNGQ3NzQzMDNjODk5ZGI2OTAyMGY5YzcwZWUxZGZjMDhjN2NlOWUiLCJzZ3hfaXN2cHJvZGlkIjowLCJzZ3hfaXN2c3ZuIjowLCJzZ3hfcmVwb3J0X2RhdGEiOiIwZTM2MjVlYTk4MGI4NGJmNzkyYTE0YWJlYzhhMDVjYjI4ZDJhMTQ4MjhkMDEyNzI3MDZlN2M1OTQwZjBmYTZiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInNneF9pc19kZWJ1Z2dhYmxlIjpmYWxzZSwic2d4X2NvbGxhdGVyYWwiOnsicWVpZGNlcnRoYXNoIjoiYjJjYTcxYjhlODQ5ZDVlNzk5NDUxYjRiZmU0MzE1OWEwZWU1NDgwMzJjZWNiMmMwZTQ3OWJmNmVlM2YzOWZkMSIsInFlaWRjcmxoYXNoIjoiZjQ1NGRjMWI5YmQ0Y2UzNmMwNDI0MWUyYzhjMzdhMmFlMjZiMDc3ZjJjNjZiOTE5ODQzMzY1MzE4YTU5MzMyYyIsInFlaWRoYXNoIjoiNGRjZDUwMWVjZTdhNzY3NWJmMDFjZDEyM2RmYmZiZDEwYzEyOTk4ZWRkNGYyMDE5ZjMxNGUxZTM1OTE4NmI5ZSIsInF1b3RlaGFzaCI6ImU0OTVjMDZjYWFmMDRkMzc4ZmQ4MDFlMWRjMDg0ZjczZDRkZDkyYjExMmVjZmZkMWU4ZTM4ODk0MWY0YzUxMDQiLCJ0Y2JpbmZvY2VydGhhc2giOiJiMmNhNzFiOGU4NDlkNWU3OTk0NTFiNGJmZTQzMTU5YTBlZTU0ODAzMmNlY2IyYzBlNDc5YmY2ZWUzZjM5ZmQxIiwidGNiaW5mb2NybGhhc2giOiJmNDU0ZGMxYjliZDRjZTM2YzA0MjQxZTJjOGMzN2EyYWUyNmIwNzdmMmM2NmI5MTk4NDMzNjUzMThhNTkzMzJjIiwidGNiaW5mb2hhc2giOiJlYzFjZWYzNzNiNWIyOThkN2JkZTM4NTI5NTE0NWQ5MmU0ZGU0MTZkMGQ1OTRlYzQ1NWVmNGU3YTMyMzUwMGY0In0sImF0dGVzdGVyX2hlbGRfZGF0YSI6IkFRQUJBRVdweWYxOWUyZUFSQ1BxL2wwN0N2a1BHSW9KSys0OHREdHY1c0I1V3N3QjJPWTYzcVN4YitEeE9yWi9iNTRCTkY2eGVTLytzN1c4MXorNVJLUXdtZXdJYWdlWlpCeVdIcDB4czZlT25ob0dNcGRERUhGaElmcDlhbjVlNHdQOHRub2FZeXplRDY2SjVXZ2QzZ1grc0J2NkdMMUJCUnE0TTFiTlZzbFhjejR3M3M0eFdXTzJDTGZnU3BJMWpBVG9FaHhMeHRhK2U1SXN0bjR2MmhYc3VFbWtlU0w1TkhyY2Z5N0FtUGhGSVNVb3l5Slo5MTIxakVrVy95bC9vR2JKZWdmZVd3RDMxNkFmNjlnYXdGQ08yOXhqdXBuZlFhN1hDUitZckIyWFRJcURxSEFibzFmUWFicmRHM0hseUlpdnlheUZZejZtb3p0djBWTW5vQWZVRnpaNzBadmNlZmNJMkhBQ28ycUlKbWF0aHlvaXN1d0gzYVowT2pjZzUzclNCc1RLOVFONGp6eVlrSWcwRGwwcHJqenJJSXlUeGVyRGYrL1IvWURUTnk5S0M2T0NsdVplMHhMbVl3RmZPY1BNcjZ0YVdWRVBETTdLOFJtdWI1SHcwMm1DUFhOaE5qT1RyUHhNNXdxckxiWDV4SjVmSnMzM3dsdjVlK1hWaTJhZ2pRPT0iLCJ2ZXJpZmllcl9ub25jZSI6eyJ2YWwiOiJUV3BhWW5KdlNWbHBlakJNY1ZKdFVIUlBPVzV5TjI5RVMyNUJRVGxwY210S05DOVVRa3A1TDJKMFVHWkJjMWRsY1hZMGEyWmFiMlZzUTBvcmNYZ3JNa3BYVVU4NFFqTkJhV2xMTkhsR1FXRnBSemhCWVdjOVBRPT0iLCJpYXQiOiJNakF5TXkweE1pMHhOaUF4T0RveE56bzFPU0FyTURBd01DQlZWRU09Iiwic2lnbmF0dXJlIjoiTEFTRVg3TDFKY3FNeEUxVDBzaDVDdTk5aGVqaHhDWmV0QVpXanNhMUdhSTBPeTh6ZnMzWW1DbVVoOExOZEJuMWhlcjc1L3VPREQ3bWFFV2R4NHNaTkhteXhLdUtwaWNabXMvbTMySTJlU0dzLyt0SCtVWlEzLytMajJMNjdlOUVMNVo4NWNLUGFKU1cyRmZQQWkrbXk2SGtGY0ZweE01Mzd6eEgvcWhKeDJVdjlXQ1NxdmRJeDlPaVRMdlQyc3ZGdzY3cXBVNFhQeGVsM1llZU85VTk0aWExNGUrVkp4WlJxUTVEbE1vOWwxZDBIZjhRK3YrY0w0Wmd6TEp1SHIzQXpQZ0JJY3VPYmN0eTlMd2JVQmRCcWRKNWZaWTBGcW1JSnJoMXZFUmlCYmV6bklJV2ZJbnczWVoyNS9wV0FCOVJXdHYrZENlSjZBcUlkQ2VCM2pGLzBGbG9DTUlDaGl5WkgwM1RTRXlpTnRlWElCR0dDUytmYkZqREZ3SHR4ZGQxVUYzcXpBcjVRSmtlUWE1elgxdjh1bUFLSXN0TWIwNzR2QXVqZzF4U3hxZTk5TUJaeWc5QVdiNy93a0JoZWJybE5oOUdlMWhlSzE2WG5RSGdqVW82MXVNOUxjTmIvcm5TSS9hWmtQMEdBTFZENHY1WCt3bmcyYngrNDI5QTNMc0YifSwiYXR0ZXN0ZXJfdGNiX3N0YXR1cyI6Ik9VVF9PRl9EQVRFIiwiYXR0ZXN0ZXJfYWR2aXNvcnlfaWRzIjpbIklOVEVMLVNBLTAwNTg2IiwiSU5URUwtU0EtMDA2MTQiLCJJTlRFTC1TQS0wMDYxNSIsIklOVEVMLVNBLTAwNjU3IiwiSU5URUwtU0EtMDA3MzAiLCJJTlRFTC1TQS0wMDczOCIsIklOVEVMLVNBLTAwNzY3IiwiSU5URUwtU0EtMDA4MjgiLCJJTlRFTC1TQS0wMDgzNyJdLCJhdHRlc3Rlcl90eXBlIjoiU0dYIiwidmVyaWZpZXJfaW5zdGFuY2VfaWRzIjpbIjkwYzYyMjY0LWU4NTQtNGZjNi05YzlkLWM3NWM4NWRhYjM1MSIsIjMwY2JmNDZkLTU5YjAtNGQ5Ni1hOTY4LWQzZDU0YzE2ZTAzNSIsIjgxZTVjYjFlLWRiYmItNDZlMi1iNmM2LTU4MjdmNzkzYjNlZiJdLCJkYmdzdGF0IjoiZGlzYWJsZWQiLCJlYXRfcHJvZmlsZSI6Imh0dHBzOi8vYW1iZXItcG9jLXVzZXIxLnByb2plY3QtYW1iZXItc21hcy5jb20vZWF0X3Byb2ZpbGUiLCJpbnR1c2UiOiJnZW5lcmljIiwidmVyIjoiMS4wLjAiLCJleHAiOjE3MDI3NTA5NzksImp0aSI6ImNjYWZlMWRmLTkyOWUtNDU5Ni1hZDE2LWQwMzk5ODYyMWIxNCIsImlhdCI6MTcwMjc1MDY3OSwiaXNzIjoiSW50ZWwgVHJ1c3QgQXV0aG9yaXR5IiwibmJmIjoxNzAyNzUwNjc5fQ.OYgfNXW3UP7y9r27mIJUsPz_Tj8_akBWQiDoXZcfFRbQKxySIX8VWz0cCDpG_838yDU2zrbqigbf9ux73syWINCZhceBNsxcU7gUGkEoAluv3grsBl_x39USGXCj9GnnuzqdNznjIIjjEO3PmMwkxeCQ_PNwNzkf611aETQnm-a1Xd34Iv9YwERpRYIrknlk2MTKLDn9QWi_lcq95YZYHuKnD8Hp9dnBwTElr5Qj5PPPIe48UVfwYJlFIqAG0fRTnRGHQtCDvOAFbPsgLleNSzbvu2Ja03A7PP08_73KiYj5sb0iqrW7hiUwEQmwz-mCQ8ppJqFgSKF4AqlxJJKb0PIDtQ8gEFlxwz6Jcw6qISnpGuflb41NSshIn7bNHEH8vRPsigHHiqgM9koMxzMcwJ7NCcq76HPaBGNWuu5Ho0tYfebWYyJ2YH2PJ0TAVgfXE5ZcqjVdtE_pqmnLNOOyGYVk_oUqERNcdWCTwzAlbqPr5ijRRI5YUwLKrHuV7_hG"
	tdxToken  = "eyJhbGciOiJQUzM4NCIsImprdSI6Imh0dHBzOi8vcG9ydGFsLnBpbG90LnRydXN0YXV0aG9yaXR5LmludGVsLmNvbS9jZXJ0cyIsImtpZCI6ImZlMmNjZTI0NGU2ODc3YzhhZDg0YjFmM2JjY2JhMWViZDJkMTJlYmMzNGQ4NzNkYzVlYTcxYjBiNWQxMmE3OWM1MzM0Mzk3YzFhMmVhZWIyNTY1NzEzM2E5ZDlmNmY2OCIsInR5cCI6IkpXVCJ9.ewogICJ0ZHhfdGVlX3RjYl9zdm4iOiAiMDQwMDA2MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLAogICJ0ZHhfbXJzZWFtIjogIjQ4ZmE2OTk0OWRiMDgwMDJlZTg0MjUyODQ3ZjU3Mjk4OGIxZDZlNTY4ZWMxMzUzZjY0Y2I2YzBmZDkwNTM3NWY2OWFkOTU5YzBlYWY3NzQ3YWM3MGEzOTI3ODkzMDJhMSIsCiAgInRkeF9tcnNpZ25lcnNlYW0iOiAiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwKICAidGR4X3NlYW1fYXR0cmlidXRlcyI6ICIwMDAwMDAwMDAwMDAwMDAwIiwKICAidGR4X3RkX2F0dHJpYnV0ZXMiOiAiMDAwMDAwMTAwMDAwMDAwMCIsCiAgInRkeF94ZmFtIjogImU3MWEwNjAwMDAwMDAwMDAiLAogICJ0ZHhfbXJ0ZCI6ICJiN2RlODAxNjBlNGI1YzJhNTNmYzlmN2ZkNzI4MzM0NTU1NjM0MzFhMDZhZTAyMjIyMWI0ZjgxYzExZWE1NWRkNGQ4OTdkMmE1MzNlODc3YzY4NDU3N2I0ODAzZDM5ZWMiLAogICJ0ZHhfbXJjb25maWdpZCI6ICIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLAogICJ0ZHhfbXJvd25lciI6ICIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLAogICJ0ZHhfbXJvd25lcmNvbmZpZyI6ICIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLAogICJ0ZHhfcnRtcjAiOiAiMTViMDBlODhiY2I3NjJlNWVjYjA0MWJkMTMyZTBmYjMzNTcyYmM4ODQ2OWRmNTNmMDZmNmZiZDM0ZTEzMmYyM2EzMDEwMzFjZTUzNThjYmI2Y2NkY2EwYWFkYmEzMjhkIiwKICAidGR4X3J0bXIxIjogIjQ1ZDhmYzBiNjAxOGE1NjU0NzQ0MWZiODA4MWM3ZWU2ZGUwNGU2MzIyMWM3ZTJiMzdkNGQ3MWZlMzYyMzEwN2U3ZTQ5NjY3ZjJkNmIyNTk3YmM1ZjA2NjNjODRiNjQ1NyIsCiAgInRkeF9ydG1yMiI6ICIyMTc0YTE3NjQ1ZDVmNTdlMTdkZGQyOGY5NWUxOGMyZDZmZTc1YTE5MjRjMDBlODYxYjU3MGU3YmUyYWRlZDYzNzY2OWUxYjAxODE2NjVjM2U5N2FiNDMyNTY2MGVkNzYiLAogICJ0ZHhfcnRtcjMiOiAiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwKICAidGR4X3JlcG9ydF9kYXRhIjogIjExNjYxYWVmZTVhMTQwN2M3NDBhZTNjMTNlMzY5MzBhN2ZiNTFhYTI5YWZiNDQ0YjUyNTRiZGEwMjUyZTk2MzgyZDA3YmNkNmE0MmU3ZGI5ODFmZmY0MDU4NWJiMTI2MDU5YTA5ZGYzZGE0Y2RmYTU2YjI5YWVlYTVjOGE5OWE2IiwKICAidGR4X3NlYW1zdm4iOiA0LAogICJ0ZHhfdGRfYXR0cmlidXRlc19kZWJ1ZyI6IGZhbHNlLAogICJ0ZHhfdGRfYXR0cmlidXRlc19zZXB0dmVfZGlzYWJsZSI6IHRydWUsCiAgInRkeF90ZF9hdHRyaWJ1dGVzX3Byb3RlY3Rpb25fa2V5cyI6IGZhbHNlLAogICJ0ZHhfdGRfYXR0cmlidXRlc19rZXlfbG9ja2VyIjogZmFsc2UsCiAgInRkeF90ZF9hdHRyaWJ1dGVzX3BlcmZtb24iOiBmYWxzZSwKICAidGR4X2lzX2RlYnVnZ2FibGUiOiBmYWxzZSwKICAidGR4X2NvbGxhdGVyYWwiOiB7CiAgICAicWVpZGNlcnRoYXNoIjogImIyY2E3MWI4ZTg0OWQ1ZTc5OTQ1MWI0YmZlNDMxNTlhMGVlNTQ4MDMyY2VjYjJjMGU0NzliZjZlZTNmMzlmZDEiLAogICAgInFlaWRjcmxoYXNoIjogImY0NTRkYzFiOWJkNGNlMzZjMDQyNDFlMmM4YzM3YTJhZTI2YjA3N2YyYzY2YjkxOTg0MzM2NTMxOGE1OTMzMmMiLAogICAgInFlaWRoYXNoIjogIjdhY2FkODM3NjkyY2NjY2VjMGJlNzM2ZDBjZGU2YWFiNDY1ZDY4NTZjYzFmZDJjMjM3ZmYwMzkzNmQ3NTY2NjQiLAogICAgInF1b3RlaGFzaCI6ICI1NjMzMmY0NGJmNTMzMWRhODBjM2E3ZjY3OWEzNjU1N2E1MWU4YjVjZGQzYzViMGE2NTU5YzcyOTY4MTVkYTE5IiwKICAgICJ0Y2JpbmZvY2VydGhhc2giOiAiYjJjYTcxYjhlODQ5ZDVlNzk5NDUxYjRiZmU0MzE1OWEwZWU1NDgwMzJjZWNiMmMwZTQ3OWJmNmVlM2YzOWZkMSIsCiAgICAidGNiaW5mb2NybGhhc2giOiAiZjQ1NGRjMWI5YmQ0Y2UzNmMwNDI0MWUyYzhjMzdhMmFlMjZiMDc3ZjJjNjZiOTE5ODQzMzY1MzE4YTU5MzMyYyIsCiAgICAidGNiaW5mb2hhc2giOiAiOGJmMjZkNWVjYzFmNTQwNDU4N2VmZmEzNTdiODU1OWVkYzA2Mzk5MDVmNGQ2OTU3ZmYxNTcyZjMzZWE1NGU5ZCIKICB9LAogICJhdHRlc3Rlcl9oZWxkX2RhdGEiOiAiQVFBQkFFV3B5ZjE5ZTJlQVJDUHEvbDA3Q3ZrUEdJb0pLKzQ4dER0djVzQjVXc3dCMk9ZNjNxU3hiK0R4T3JaL2I1NEJORjZ4ZVMvK3M3Vzgxeis1UktRd21ld0lhZ2VaWkJ5V0hwMHhzNmVPbmhvR01wZERFSEZoSWZwOWFuNWU0d1A4dG5vYVl5emVENjZKNVdnZDNnWCtzQnY2R0wxQkJScTRNMWJOVnNsWGN6NHczczR4V1dPMkNMZmdTcEkxakFUb0VoeEx4dGErZTVJc3RuNHYyaFhzdUVta2VTTDVOSHJjZnk3QW1QaEZJU1VveXlKWjkxMjFqRWtXL3lsL29HYkplZ2ZlV3dEMzE2QWY2OWdhd0ZDTzI5eGp1cG5mUWE3WENSK1lyQjJYVElxRHFIQWJvMWZRYWJyZEczSGx5SWl2eWF5Rll6Nm1venR2MFZNbm9BZlVGelo3MFp2Y2VmY0kySEFDbzJxSUptYXRoeW9pc3V3SDNhWjBPamNnNTNyU0JzVEs5UU40anp5WWtJZzBEbDBwcmp6cklJeVR4ZXJEZisvUi9ZRFROeTlLQzZPQ2x1WmUweExtWXdGZk9jUE1yNnRhV1ZFUERNN0s4Um11YjVIdzAybUNQWE5oTmpPVHJQeE01d3FyTGJYNXhKNWZKczMzd2x2NWUrWFZpMmFnalE9PSIsCiAgInZlcmlmaWVyX25vbmNlIjogewogICAgInZhbCI6ICJPR1JGTjFOa2JUZ3ZVSFZJTTI5VVNEazJZbmh1TkRGUVdGZFlia1Y2YlZwTmEyRkRTR05ZWms5eVpEWldWVFYyV1dvNVpHNXphQ3RDVXpnM2VXcFlWM0psY0ZRM1QwczFaMlF6Ykd4M1ZERjZhV0YyTDBFOVBRPT0iLAogICAgImlhdCI6ICJNakF5TkMwd01pMHdNU0F3Tmpvek9Eb3pNU0FyTURBd01DQlZWRU09IiwKICAgICJzaWduYXR1cmUiOiAiYlhmRDNaK3NsNjhWa3AyREdOTHIyRHBJSlhObHFVaTZnT0I3aG0rOFhJVlpYQjYwZEpMbytuSUNRMXZsRGhUbkVncUp1WUtlL29ZL1BpN3I3clhBUHJaRUNwUE1LdDZIQ2hYbjI1T2hpcVN4eFo3VzMwVjhWb0p3V0YvTkl6QmVXeXByRDJpYjQwVVR3SEpMQys5VzJOSG1pU28rN29heXFTeTFtdlh4VnYxNjdoVzBQZDlZZVlKUGVzLzNXTjRqT0tLZ2x2VjJJdjZ0WnpYaFJESGhoRGFFYjZhNk5oeGtYQ3FrMDB2bW5vQ0pFbEJ5M1dWN0hmN3hwVGV3MHVoVDU5MDJEWWRVS2lQOWdDRjZqSnM1R3U0SUdMNUR5STdtVXZlbi84WFdMRGZmeVlJRmdWZzFlVkdtS3c4L0djVUhZcVlnckdrMkIxVWNYZnhveXVTQ0tVeFM4NlBBd05GVS9INnFTdU9wWTVybU40c240UTNKamtNMU5YNjlPTlV4aW5xUGl6QmdFT2QxbW9aQnM0aTFsUTVDZWxFUS9zWG9nUGdYazg3Um9qVWNpaGk1TVFrNTNweVY0Z3RRemR6NlVibTA4T0I4Sy8zZFhXbDJOc1RDMmMrSm82RkN6K29aV3BXUjdDN0F4T3NQMVZ1dTB6ZnQrTlRJZzQvYUJWTnIiCiAgfSwKICAiYXR0ZXN0ZXJfdGNiX3N0YXR1cyI6ICJVcFRvRGF0ZSIsCiAgImF0dGVzdGVyX3RjYl9kYXRlIjogIjIwMjMtMDgtMDlUMDA6MDA6MDBaIiwKICAiYXR0ZXN0ZXJfdHlwZSI6ICJURFgiLAogICJ2ZXJpZmllcl9pbnN0YW5jZV9pZHMiOiBbCiAgICAiMDUxYTkxYjEtMzFjZC00MWNlLTgzOTAtNmJmODQ0YjFjM2M2IiwKICAgICI5ZGZmYTI4NS1hMTJhLTQ3YzktYWIwYi05ZjAwODdlODAyNzQiLAogICAgIjJlNzI2YzUxLWU1MWUtNGVlMC05ZWY4LTI4MWZlYmQyY2Q3ZSIKICBdLAogICJkYmdzdGF0IjogImRpc2FibGVkIiwKICAiZWF0X3Byb2ZpbGUiOiAiaHR0cHM6Ly9wb3J0YWwucGlsb3QudHJ1c3RhdXRob3JpdHkuaW50ZWwuY29tL2VhdF9wcm9maWxlLmh0bWwiLAogICJpbnR1c2UiOiAiZ2VuZXJpYyIsCiAgInZlciI6ICIxLjAuMCIsCiAgImV4cCI6IDE3MDY3Njk4MTEsCiAgImp0aSI6ICIwNzQ4YzEwNS00ZTc1LTQyMzMtYWMxOS0wMDRmZWY2MzIxNmMiLAogICJpYXQiOiAxNzA2NzY5NTExLAogICJpc3MiOiAiSW50ZWwgVHJ1c3QgQXV0aG9yaXR5IiwKICAibmJmIjogMTcwNjc2OTUxMQp9.Zbx7bC3T2ix6lJSmTUbyAtX9d_tF_tUBCQM-bY8h8j9QSLYKgyUp8MWH0OQ1P4CZQldgyk6Sf0HjtZyuDlLZb-rgn-LaHG-xHdjkFcPEg_REmnzoBzLxDaKRyWjiJtuPWqi7pAEA998fpN6z06HF4t6gpLVCkMVNv_LBRdy1SmVN9VAuwZYBbMmM6j0EZ7XCIK5PqlmWua61dE-lx0UX17Bf9-BJUlE33nc0Hd0P51Tdgzz-klRzhcLYl3wEWxXuz4GXyEolQwTTVWU11dkYKPu13ZzQqsuXj5wZKuljKvQ-7tYA22TsGjIM-VUP6LfMOdPRV8zW_jpTPuNVMS97vuS1kjVGgazoZRUCn4P4vCZmlxZKJ1lJsO_aft8MZ2pFJTyAugxO1rkDZ9_fxgTiLTsCOyT8dRkpf3QFGwuBXNMV7vghdn4_sjlMBNvjyYmVD0_4vFogqxbbMw4n4b_22j4OlbUZBmFWsOyv4gY3WQjzAqztxFZ60RwTkLqK7YaY"
	nonceResp = itaConnector.GetNonceResponse{
		Nonce:   nonce,
		Headers: nil,
	}
	sgxTokenResp = itaConnector.GetTokenResponse{
		Token:   sgxToken,
		Headers: nil,
	}
	tdxTokenResp = itaConnector.GetTokenResponse{
		Token:   tdxToken,
		Headers: nil,
	}
	sgxAttestResp = itaConnector.AttestResponse{Token: sgxToken}
	tdxAttestResp = itaConnector.AttestResponse{Token: tdxToken}
)

func TestKeyTransferRSA(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	itaClientConnector.On("AttestEvidence", mock.Anything, mock.Anything, mock.Anything).Return(sgxAttestResp, nil).Once()
	jwtToken := parseJWTToken(sgxToken, []byte(""))
	itaClientConnector.On("VerifyToken", mock.Anything).Return(jwtToken, nil).Once()

	kmipClient.On("GetKey", mock.Anything, mock.Anything).Return(key, nil)
	kmipKeyManager.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return([]uint8(key), nil)

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	nonce := &itaConnector.VerifierNonce{}

	transReq := &model.KeyTransferRequest{
		Quote:         []byte(""),
		VerifierNonce: nonce,
		RuntimeData:   []byte(""),
		EventLog:      []byte(""),
	}

	request := TransferKeyRequest{
		KeyId:              uuid.MustParse("87d59b82-33b7-47e7-8fcb-6f7f12c82719"),
		AttestationType:    "SGX",
		KeyTransferRequest: transReq,
	}

	_, err := svc.TransferKeyWithEvidence(context.Background(), request)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestSGXKeyTransfer(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	itaClientConnector.On("AttestEvidence", mock.Anything, mock.Anything, mock.Anything).Return(sgxAttestResp, nil).Once()
	jwtToken := parseJWTToken(sgxToken, []byte(""))
	itaClientConnector.On("VerifyToken", mock.Anything).Return(jwtToken, nil).Once()

	kmipClient.On("GetKey", mock.Anything, mock.Anything).Return(key, nil)
	kmipKeyManager.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return([]uint8(key), nil)

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	nonce := &itaConnector.VerifierNonce{}

	transReq := &model.KeyTransferRequest{
		Quote:         []byte(""),
		VerifierNonce: nonce,
		RuntimeData:   []byte(""),
		EventLog:      []byte(""),
	}

	request := TransferKeyRequest{
		KeyId:              uuid.MustParse("e57e5ea0-d465-461e-882d-1600090caa0d"),
		AttestationType:    "SGX",
		KeyTransferRequest: transReq,
	}

	_, err := svc.TransferKeyWithEvidence(context.Background(), request)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestTDXKeyTransfer(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	itaClientConnector.On("AttestEvidence", mock.Anything, mock.Anything, mock.Anything).Return(tdxAttestResp, nil).Once()
	jwtToken := parseJWTToken(tdxToken, []byte(""))
	itaClientConnector.On("VerifyToken", mock.Anything).Return(jwtToken, nil).Once()

	kmipClient.On("GetKey", mock.Anything, mock.Anything).Return(key, nil)
	kmipKeyManager.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return([]uint8(key), nil)

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	nonce := &itaConnector.VerifierNonce{}

	transReq := &model.KeyTransferRequest{
		Quote:         []byte(""),
		VerifierNonce: nonce,
		RuntimeData:   []byte(""),
		EventLog:      []byte(""),
	}

	request := TransferKeyRequest{
		KeyId:              uuid.MustParse("ed37c360-7eae-4250-a677-6ee12adce8e3"),
		AttestationType:    "TDX",
		KeyTransferRequest: transReq,
	}

	_, err := svc.TransferKeyWithEvidence(context.Background(), request)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestKeyTransferInvalidAttestationType(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	request := TransferKeyRequest{
		KeyId:           uuid.MustParse("ed37c360-7eae-4250-a677-6ee12adce8e3"),
		AttestationType: "Invalid",
	}

	_, err := svc.TransferKeyWithEvidence(context.Background(), request)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestKeyTransferInvalidKeyId(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	request := TransferKeyRequest{
		KeyId:           uuid.New(),
		AttestationType: "SGX",
	}

	_, err := svc.TransferKeyWithEvidence(context.Background(), request)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestKeyTransferInvalidAttestationToken(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	// Return an SGX token for a TDX-policy key — claim validation rejects it.
	itaClientConnector.On("AttestEvidence", mock.Anything, mock.Anything, mock.Anything).Return(sgxAttestResp, nil).Once()
	jwtToken := parseJWTToken(sgxToken, []byte(""))
	itaClientConnector.On("VerifyToken", mock.Anything).Return(jwtToken, nil).Once()

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	transReq := &model.KeyTransferRequest{}

	request := TransferKeyRequest{
		KeyId:              uuid.MustParse("ed37c360-7eae-4250-a677-6ee12adce8e3"),
		AttestationType:    "TDX",
		KeyTransferRequest: transReq,
	}

	_, err := svc.TransferKeyWithEvidence(context.Background(), request)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestKeyTransferWithoutEvidence(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	// No attestation_token and no Attestation-Type header should return 400.
	transReq := &model.KeyTransferRequest{}
	request := TransferKeyRequest{
		KeyId:              uuid.MustParse("ed37c360-7eae-4250-a677-6ee12adce8e3"),
		KeyTransferRequest: transReq,
	}

	_, err := svc.TransferKeyWithEvidence(context.Background(), request)
	g.Expect(err).To(gomega.HaveOccurred())
	handledErr, ok := err.(*HandledError)
	g.Expect(ok).To(gomega.BeTrue())
	g.Expect(handledErr.Code).To(gomega.Equal(http.StatusBadRequest))
}

func TestGetPublicKey_WithMissingAttesterHeldData_ReturnsError(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	publicKey, err := getPublicKey("", model.TDX)

	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.Equal("attester held data is missing or invalid"))
	g.Expect(publicKey).To(gomega.BeNil())
}

// TestGetPublicKey_ShortData exercises the bounds-check guard for inputs that
// decode to fewer than 5 bytes.  Before the fix these would panic with a
// runtime slice-bounds error (CWE-129 / DoS).
func TestGetPublicKey_ShortData_ReturnsError(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	cases := []struct {
		name    string
		decoded []byte
	}{
		{"0 bytes", []byte{}},
		{"3 bytes", []byte{0x01, 0x02, 0x03}},
		{"4 bytes", []byte{0x00, 0x00, 0x10, 0x01}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encoded := base64.StdEncoding.EncodeToString(tc.decoded)
			key, err := getPublicKey(encoded, model.TDX)
			g.Expect(err).To(gomega.HaveOccurred(), "expected error for %s", tc.name)
			g.Expect(err.Error()).To(gomega.Equal("attester held data is missing or invalid"))
			g.Expect(key).To(gomega.BeNil())
		})
	}
}

// TestGetPolicyIDsForAttestationTypes_FiltersUnused verifies that sub-policy IDs
// are only collected for attester types listed in AttestationType, and that stale
// sub-policy objects for unlisted types are ignored.
func TestGetPolicyIDsForAttestationTypes_FiltersUnused(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	tdxID := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	sgxID := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	nvgpuID := uuid.MustParse("cccccccc-cccc-cccc-cccc-cccccccccccc")

	policy := &model.KeyTransferPolicy{
		AttestationType: model.AttesterTypes{model.TDX},
		TDX:             &model.TdxPolicy{PolicyIds: []uuid.UUID{tdxID}},
		SGX:             &model.SgxPolicy{PolicyIds: []uuid.UUID{sgxID}},     // not in AttestationType
		NVGPU:           &model.NvgpuPolicy{PolicyIds: []uuid.UUID{nvgpuID}}, // not in AttestationType
	}

	ids := getPolicyIDsForAttestationTypes(policy)
	g.Expect(ids).To(gomega.HaveLen(1))
	g.Expect(ids[0]).To(gomega.Equal(tdxID))
}

// TestGetPolicyIDsForAttestationTypes_Composite verifies all sub-policies are
// included when AttestationType lists all types.
func TestGetPolicyIDsForAttestationTypes_Composite(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	tdxID := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	nvgpuID := uuid.MustParse("cccccccc-cccc-cccc-cccc-cccccccccccc")

	policy := &model.KeyTransferPolicy{
		AttestationType: model.AttesterTypes{model.TDX, model.NVGPU},
		TDX:             &model.TdxPolicy{PolicyIds: []uuid.UUID{tdxID}},
		NVGPU:           &model.NvgpuPolicy{PolicyIds: []uuid.UUID{nvgpuID}},
	}

	ids := getPolicyIDsForAttestationTypes(policy)
	g.Expect(ids).To(gomega.HaveLen(2))
}

// TestSGXKeyTransfer_AttestationTypeInResponse verifies that a successful key
// transfer populates TransferKeyResponse.AttestationType from the token claims.
func TestSGXKeyTransfer_AttestationTypeInResponse(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	itaClientConnector.On("AttestEvidence", mock.Anything, mock.Anything, mock.Anything).Return(sgxAttestResp, nil).Once()
	jwtToken := parseJWTToken(sgxToken, []byte(""))
	itaClientConnector.On("VerifyToken", mock.Anything).Return(jwtToken, nil).Once()

	kmipClient.On("GetKey", mock.Anything, mock.Anything).Return(key, nil)
	kmipKeyManager.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return([]uint8(key), nil)

	svc := LoggingMiddleware()(svcInstance)
	transReq := &model.KeyTransferRequest{
		Quote:         []byte(""),
		VerifierNonce: &itaConnector.VerifierNonce{},
		RuntimeData:   []byte(""),
	}

	request := TransferKeyRequest{
		KeyId:              uuid.MustParse("87d59b82-33b7-47e7-8fcb-6f7f12c82719"),
		AttestationType:    "SGX",
		KeyTransferRequest: transReq,
	}

	resp, err := svc.TransferKeyWithEvidence(context.Background(), request)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(resp.AttestationType).To(gomega.Equal("SGX"))
}

// TestTDXKeyTransfer_AttestationTypeInResponse verifies the same for TDX.
func TestTDXKeyTransfer_AttestationTypeInResponse(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	itaClientConnector.On("AttestEvidence", mock.Anything, mock.Anything, mock.Anything).Return(tdxAttestResp, nil).Once()
	jwtToken := parseJWTToken(tdxToken, []byte(""))
	itaClientConnector.On("VerifyToken", mock.Anything).Return(jwtToken, nil).Once()

	kmipClient.On("GetKey", mock.Anything, mock.Anything).Return(key, nil)
	kmipKeyManager.On("TransferKey", mock.AnythingOfType("*model.KeyAttributes")).Return([]uint8(key), nil)

	svc := LoggingMiddleware()(svcInstance)
	transReq := &model.KeyTransferRequest{
		Quote:         []byte(""),
		VerifierNonce: &itaConnector.VerifierNonce{},
		RuntimeData:   []byte(""),
		EventLog:      []byte(""),
	}

	request := TransferKeyRequest{
		KeyId:              uuid.MustParse("ed37c360-7eae-4250-a677-6ee12adce8e3"),
		AttestationType:    "TDX",
		KeyTransferRequest: transReq,
	}

	resp, err := svc.TransferKeyWithEvidence(context.Background(), request)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(resp.AttestationType).To(gomega.Equal("TDX"))
}

// ParseJWTToken parses a JWT token string and returns a jwt.Token object.
func parseJWTToken(tokenString string, secretKey []byte) *jwtlib.Token {
	token, _ := jwtlib.Parse(tokenString, func(token *jwtlib.Token) (interface{}, error) {
		return secretKey, nil
	})

	return token
}
