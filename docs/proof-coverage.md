# Proof coverage

Per-subprogram SPARK proof status across the workspace,
rendered straight from `gnatprove/gnatprove.out` (workspace
umbrella `transports_spark.gpr` + `gnatprove -U --level=4
--proof-warnings=on`). Refresh with
`make prove && make prove-coverage`.

**Workspace totals:** 3269 / 3441 subprograms fully proved · 30,082 / 30,660 VCs (98%).

## Legend

Status comes directly from `gnatprove/gnatprove.out` at
`--level=4` — no source-annotation cross-check, no claim layer.

| Symbol | Meaning |
|---|---|
| 🟢 | All VCs in this subprogram / package are proved |
| 🟡 | Partial — at least one VC unproved |
| ⚪ | Not analysed (skipped, `SPARK_Mode (Off)`, or zero VCs) |


<details>
<summary>🟡 <b>tls_core</b> — 117/160 subprograms · 4,439/4,716 VCs (94%)</summary>

<details>
<summary>🟢 <code>Tls_Core.Alert</code> — 2/2 subprograms · 8/8 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Decode` | 7/7 |
| 🟢 | `Encode` | 1/1 |

</details>

<details>
<summary>🟢 <code>Tls_Core.Cert</code> — 6/6 subprograms · 116/116 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Equal_At` | 7/7 |
| 🟢 | `Find_SAN_Ext` | 19/19 |
| 🟢 | `Iequal` | 5/5 |
| 🟢 | `Match_DNS_SAN` | 19/19 |
| 🟢 | `Parse` | 40/40 |
| 🟢 | `Read_Tlv` | 26/26 |

</details>

<details>
<summary>🟢 <code>Tls_Core.Cert_Chain</code> — 5/5 subprograms · 280/280 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Authenticate_Server` | 31/31 |
| 🟢 | `Parse_Ecdsa_Sig_Der` | 24/24 |
| 🟢 | `Validate_Chain` | 139/139 |
| 🟢 | `Verify_Cert_Verify` | 45/45 |
| 🟢 | `Verify_Signed_TBS` | 41/41 |

</details>

<details>
<summary>🟢 <code>Tls_Core.Cert_Chain.Parse_Ecdsa_Sig_Der</code> — 1/1 subprograms · 28/28 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Read_Tlv_Small` | 28/28 |

</details>

<details>
<summary>🟢 <code>Tls_Core.Cert_Verify</code> — 9/9 subprograms · 198/198 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Append_Der_Integer` | 46/46 |
| 🟢 | `Build_Signed_Content` | 18/18 |
| 🟢 | `Decode_Body` | 15/15 |
| 🟢 | `Decode_Body_Single` | 43/43 |
| 🟢 | `Encode_Body` | 15/15 |
| 🟢 | `Encode_Body_Single` | 24/24 |
| 🟢 | `Encode_Ecdsa_Sig_Der` | 9/9 |
| 🟢 | `Put_U16` | 10/10 |
| 🟢 | `Put_U24` | 18/18 |

</details>

<details>
<summary>🟡 <code>Tls_Core.Client_Hello_Rflx</code> — 11/12 subprograms · 268/269 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `CH_Random` | 1/1 |
| 🟢 | `CH_Sid_Len` | 2/2 |
| 🟢 | `CH_Suites_First` | 5/5 |
| 🟢 | `CH_Suites_Len` | 8/8 |
| 🟢 | `CH_Suites_Len_Off` | 3/3 |
| 🟢 | `CH_Valid` | 8/8 |
| 🟢 | `Decode_Client_Hello_Fields` | 52/52 |
| 🟢 | `Decode_Client_Hello_Psk` | 38/38 |
| 🟢 | `Encode_Client_Hello_Core` | 73/73 |
| 🟢 | `Lemma_CH_Round_Trip` | 22/22 |
| 🟢 | `Rflx_Validate_Ch` | 22/22 |
| 🟡 | `Decode_Client_Hello_Cert` | 34/35 |

</details>

<details>
<summary>🟡 <code>Tls_Core.Ext_Walk_Rflx</code> — 0/5 subprograms · 187/197 VCs (95%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟡 | `Find_Key_Share_X25519` | 58/61 |
| 🟡 | `Find_Key_Share_X25519_Sh` | 21/22 |
| 🟡 | `Find_Psk_Fields` | 43/44 |
| 🟡 | `Find_Sig_Algs` | 16/17 |
| 🟡 | `Walk_Find` | 49/53 |

</details>

<details>
<summary>🟡 <code>Tls_Core.Extensions</code> — 4/6 subprograms · 100/102 VCs (98%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Decode_Alpn` | 12/12 |
| 🟢 | `Decode_Server_Name` | 26/26 |
| 🟢 | `Encode_Alpn` | 14/14 |
| 🟢 | `Encode_Server_Name` | 19/19 |
| 🟡 | `Append_Alpn_Name` | 19/20 |
| 🟡 | `Put_U16` | 10/11 |

</details>

<details>
<summary>🟢 <code>Tls_Core.Finished</code> — 1/1 subprograms · 2/2 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Compute` | 2/2 |

</details>

<details>
<summary>🟢 <code>Tls_Core.Finished.Hkdf_Expand_Label_Sha256gp320</code> — 2/2 subprograms · 41/41 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Hkdf_Expand_Label_Sha256` | 25/25 |
| 🟢 | `Hmac_Expand` | 16/16 |

</details>

<details>
<summary>🟢 <code>Tls_Core.Handshake</code> — 2/2 subprograms · 176/176 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Derive_Ecdhe_Secrets` | 88/88 |
| 🟢 | `Derive_Psk_Secrets` | 88/88 |

</details>

<details>
<summary>🟢 <code>Tls_Core.Handshake_Buffer</code> — 5/5 subprograms · 64/64 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Buffer` | 1/1 |
| 🟢 | `Init` | 3/3 |
| 🟢 | `Peek_Body_Length` | 1/1 |
| 🟢 | `Pop_Complete_Message` | 35/35 |
| 🟢 | `Push_Record_Bytes` | 24/24 |

</details>

<details>
<summary>🟡 <code>Tls_Core.Hello</code> — 2/12 subprograms · 1,439/1,663 VCs (87%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Encode_Server_Hello_Cert` | 91/91 |
| 🟢 | `Encode_Server_Hello_Psk` | 109/109 |
| 🟡 | `Decode_Client_Hello` | 43/62 |
| 🟡 | `Decode_Client_Hello_Cert` | 70/98 |
| 🟡 | `Decode_Client_Hello_Psk` | 106/142 |
| 🟡 | `Decode_Server_Hello` | 37/54 |
| 🟡 | `Decode_Server_Hello_Psk_Key_Share` | 32/49 |
| 🟡 | `Encode_Client_Hello` | 134/136 |
| 🟡 | `Encode_Client_Hello_Cert` | 200/223 |
| 🟡 | `Encode_Client_Hello_Psk` | 249/289 |
| 🟡 | `Encode_Client_Hello_Psk_With_Cookie` | 276/316 |
| 🟡 | `Encode_Server_Hello` | 92/94 |

</details>

<details>
<summary>🟢 <code>Tls_Core.Hello_Retry</code> — 9/9 subprograms · 186/186 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Build_Synthetic_Msg_Sha256` | 31/31 |
| 🟢 | `Cookies_Equal` | 10/10 |
| 🟢 | `Decode_Hrr` | 65/65 |
| 🟢 | `Encode_Hrr` | 34/34 |
| 🟢 | `Is_Hrr_Random` | 5/5 |
| 🟢 | `Patch_U16` | 7/7 |
| 🟢 | `W_Bytes` | 19/19 |
| 🟢 | `W_U16` | 11/11 |
| 🟢 | `W_U8` | 4/4 |

</details>

<details>
<summary>🟢 <code>Tls_Core.Hello_Rflx</code> — 10/10 subprograms · 178/178 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Decode_Server_Hello_Fields` | 39/39 |
| 🟢 | `Decode_Server_Hello_Key_Share` | 29/29 |
| 🟢 | `Encode_Server_Hello_Core` | 38/38 |
| 🟢 | `Lemma_Round_Trip` | 29/29 |
| 🟢 | `Rflx_Validate` | 22/22 |
| 🟢 | `Spec_Random` | 1/1 |
| 🟢 | `Spec_Sid_Len` | 2/2 |
| 🟢 | `Spec_Suite_Code` | 7/7 |
| 🟢 | `Spec_Suite_Offset` | 4/4 |
| 🟢 | `Spec_Valid` | 7/7 |

</details>

<details>
<summary>🟢 <code>Tls_Core.Hkdf_Label_Sha384.Expand_Labelgp453</code> — 2/2 subprograms · 41/41 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Expand_Label` | 25/25 |
| 🟢 | `Hmac_Expand` | 16/16 |

</details>

<details>
<summary>🟡 <code>Tls_Core.Key_Sched</code> — 5/6 subprograms · 59/61 VCs (97%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Build_Finished` | 8/8 |
| 🟢 | `Derive_App_Secrets` | 16/16 |
| 🟢 | `Derive_Handshake_Secrets` | 23/23 |
| 🟢 | `Derive_Resumption_Master_Secret` | 5/5 |
| 🟢 | `Init_Hs_Channel` | 7/7 |
| 🟡 | `Transcript_Append` | 0/2 |

</details>

<details>
<summary>🟢 <code>Tls_Core.Key_Sched.Exp256gp1466</code> — 2/2 subprograms · 41/41 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Exp256` | 25/25 |
| 🟢 | `Hmac_Expand` | 16/16 |

</details>

<details>
<summary>🟡 <code>Tls_Core.Key_Sched.Exp384gp1641</code> — 0/2 subprograms · 37/41 VCs (90%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟡 | `Exp384` | 23/25 |
| 🟡 | `Hmac_Expand` | 14/16 |

</details>

<details>
<summary>🟡 <code>Tls_Core.Key_Schedule</code> — 1/2 subprograms · 2/3 VCs (67%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Extract` | 1/1 |
| 🟡 | `Derive_Secret` | 1/2 |

</details>

<details>
<summary>🟢 <code>Tls_Core.Key_Schedule.Hkdf_Expand_Label_Sha256gp1072</code> — 2/2 subprograms · 41/41 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Hkdf_Expand_Label_Sha256` | 25/25 |
| 🟢 | `Hmac_Expand` | 16/16 |

</details>

<details>
<summary>🟡 <code>Tls_Core.Key_Schedule_Sha384</code> — 1/2 subprograms · 2/3 VCs (67%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Extract` | 1/1 |
| 🟡 | `Derive_Secret` | 1/2 |

</details>

<details>
<summary>🟢 <code>Tls_Core.Key_Schedule_Sha384.Hkdf_Expand_Label_Sha384gp574</code> — 2/2 subprograms · 41/41 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Hkdf_Expand_Label_Sha384` | 25/25 |
| 🟢 | `Hmac_Expand` | 16/16 |

</details>

<details>
<summary>🟢 <code>Tls_Core.Key_Update</code> — 4/4 subprograms · 28/28 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Decode` | 13/13 |
| 🟢 | `Derive_Next_Sha256` | 1/1 |
| 🟢 | `Derive_Next_Sha384` | 1/1 |
| 🟢 | `Encode` | 13/13 |

</details>

<details>
<summary>🟡 <code>Tls_Core.Key_Update.Hkdf_Expand_Label_Sha256gp416</code> — 0/2 subprograms · 37/41 VCs (90%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟡 | `Hkdf_Expand_Label_Sha256` | 23/25 |
| 🟡 | `Hmac_Expand` | 14/16 |

</details>

<details>
<summary>⚪ <code>Tls_Core.P256_Field.Octet_Big</code> — 0/2 subprograms · 0/0 VCs (0%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| ⚪ | `From_Big_Integer` | — |
| ⚪ | `To_Big_Integer` | — |

</details>

<details>
<summary>⚪ <code>Tls_Core.P256_Field.To_I64gp3543</code> — 0/1 subprograms · 0/0 VCs (0%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| ⚪ | `To_I64` | — |

</details>

<details>
<summary>⚪ <code>Tls_Core.P256_Field.To_U64gp3460</code> — 0/1 subprograms · 0/0 VCs (0%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| ⚪ | `To_U64` | — |

</details>

<details>
<summary>⚪ <code>Tls_Core.Poly1305</code> — 0/2 subprograms · 0/0 VCs (0%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| ⚪ | `Octet_Bigint` | — |
| ⚪ | `U64_Bigint` | — |

</details>

<details>
<summary>⚪ <code>Tls_Core.Poly1305.Octet_Bigint</code> — 0/2 subprograms · 0/0 VCs (0%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| ⚪ | `From_Big_Integer` | — |
| ⚪ | `To_Big_Integer` | — |

</details>

<details>
<summary>⚪ <code>Tls_Core.Poly1305.Spec_Finish</code> — 0/1 subprograms · 0/0 VCs (0%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| ⚪ | `Big_U64` | — |

</details>

<details>
<summary>⚪ <code>Tls_Core.Poly1305.Spec_Finish.Big_U64</code> — 0/2 subprograms · 0/0 VCs (0%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| ⚪ | `From_Big_Integer` | — |
| ⚪ | `To_Big_Integer` | — |

</details>

<details>
<summary>⚪ <code>Tls_Core.Poly1305.U64_Bigint</code> — 0/2 subprograms · 0/0 VCs (0%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| ⚪ | `From_Big_Integer` | — |
| ⚪ | `To_Big_Integer` | — |

</details>

<details>
<summary>🟡 <code>Tls_Core.Psk_Binder</code> — 0/1 subprograms · 18/19 VCs (95%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟡 | `Compute` | 18/19 |

</details>

<details>
<summary>🟢 <code>Tls_Core.Psk_Binder.Exp256gp434</code> — 2/2 subprograms · 41/41 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Exp256` | 25/25 |
| 🟢 | `Hmac_Expand` | 16/16 |

</details>

<details>
<summary>🟡 <code>Tls_Core.Psk_Binder.Exp384gp609</code> — 0/2 subprograms · 37/41 VCs (90%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟡 | `Exp384` | 23/25 |
| 🟡 | `Hmac_Expand` | 14/16 |

</details>

<details>
<summary>🟢 <code>Tls_Core.Session_Cache</code> — 4/4 subprograms · 27/27 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Init` | 1/1 |
| 🟢 | `Insert` | 22/22 |
| 🟢 | `Invalidate` | 1/1 |
| 🟢 | `Lookup_Most_Recent` | 3/3 |

</details>

<details>
<summary>🟢 <code>Tls_Core.Session_Ticket</code> — 4/4 subprograms · 136/136 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Decode_Body` | 51/51 |
| 🟢 | `Derive_Psk_From_Ticket_Sha256` | 1/1 |
| 🟢 | `Derive_Resumption_Master_Secret_Sha256` | 1/1 |
| 🟢 | `Encode_Body` | 83/83 |

</details>

<details>
<summary>🟢 <code>Tls_Core.Session_Ticket.Hkdf_Expand_Label_Sha256gp476</code> — 2/2 subprograms · 41/41 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Hkdf_Expand_Label_Sha256` | 25/25 |
| 🟢 | `Hmac_Expand` | 16/16 |

</details>

<details>
<summary>🟢 <code>Tls_Core.Suites</code> — 1/1 subprograms · 1/1 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Suite_Of_Code` | 1/1 |

</details>

<details>
<summary>🟢 <code>Tls_Core.Tls13_Driver.Step_Awaiting_Ch_Cert</code> — 1/1 subprograms · 210/210 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Handle` | 210/210 |

</details>

<details>
<summary>🟢 <code>Tls_Core.Traffic_Keys</code> — 1/1 subprograms · 2/2 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Derive` | 2/2 |

</details>

<details>
<summary>🟢 <code>Tls_Core.Traffic_Keys.Hkdf_Expand_Label_Sha256gp196</code> — 2/2 subprograms · 41/41 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Hkdf_Expand_Label_Sha256` | 25/25 |
| 🟢 | `Hmac_Expand` | 16/16 |

</details>

<details>
<summary>🟢 <code>Tls_Core.Traffic_Keys_Aes128</code> — 1/1 subprograms · 2/2 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Derive` | 2/2 |

</details>

<details>
<summary>🟢 <code>Tls_Core.Traffic_Keys_Aes128.Hkdf_Expand_Label_Sha256gp203</code> — 2/2 subprograms · 41/41 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Hkdf_Expand_Label_Sha256` | 25/25 |
| 🟢 | `Hmac_Expand` | 16/16 |

</details>

<details>
<summary>🟢 <code>Tls_Core.Traffic_Keys_Aes256_Sha384</code> — 1/1 subprograms · 2/2 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Derive` | 2/2 |

</details>

<details>
<summary>🟢 <code>Tls_Core.Transcript</code> — 1/1 subprograms · 2/2 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Append` | 2/2 |

</details>

<details>
<summary>🟢 <code>Tls_Core.Transcript_Sha384</code> — 1/1 subprograms · 2/2 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Append` | 2/2 |

</details>

<details>
<summary>🟡 <code>Tls_Core.X509</code> — 0/2 subprograms · 162/185 VCs (88%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟡 | `Equal_At` | 6/7 |
| 🟡 | `Parse_Ed25519_Cert` | 156/178 |

</details>

<details>
<summary>🟢 <code>Tls_Core.X509_Spki</code> — 6/6 subprograms · 74/74 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Decode` | 15/15 |
| 🟢 | `Decode_Rsa_Key` | 5/5 |
| 🟢 | `Read_Length` | 15/15 |
| 🟢 | `Read_TLV_Header` | 28/28 |
| 🟢 | `Read_Tag` | 7/7 |
| 🟢 | `Slice_Equal` | 4/4 |

</details>

</details>

<details>
<summary>🟡 <b>http2_core</b> — 33/54 subprograms · 928/1,061 VCs (87%)</summary>

<details>
<summary>🟡 <code>Http2_Core.Flow_Gate</code> — 1/7 subprograms · 80/86 VCs (93%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Finalize` | 2/2 |
| 🟡 | `Apply_Wu_Conn` | 18/19 |
| 🟡 | `Apply_Wu_Stream` | 18/19 |
| 🟡 | `Drive_One_Cycle` | 6/7 |
| 🟡 | `Init_Stream` | 15/16 |
| 🟡 | `Initialize` | 1/2 |
| 🟡 | `Request_Send` | 20/21 |

</details>

<details>
<summary>🟡 <code>Http2_Core.Hpack</code> — 4/7 subprograms · 304/374 VCs (81%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Make_Header` | 19/19 |
| 🟢 | `Static_Table` | 61/61 |
| 🟢 | `To_Int` | 1/1 |
| 🟢 | `To_Str` | 1/1 |
| 🟡 | `Decode` | 80/104 |
| 🟡 | `Encode` | 58/76 |
| 🟡 | `Encode_With_Table` | 84/112 |

</details>

<details>
<summary>🟡 <code>Http2_Core.Hpack.Encode</code> — 0/1 subprograms · 1/6 VCs (17%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟡 | `Emit_Integer` | 1/6 |

</details>

<details>
<summary>🟡 <code>Http2_Core.Hpack.Encode_With_Table</code> — 0/1 subprograms · 1/6 VCs (17%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟡 | `Emit_Integer` | 1/6 |

</details>

<details>
<summary>🟡 <code>Http2_Core.Hpack.Huffman</code> — 1/3 subprograms · 46/54 VCs (85%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Max_Encoded_Length` | 3/3 |
| 🟡 | `Decode` | 23/26 |
| 🟡 | `Encode` | 20/25 |

</details>

<details>
<summary>🟢 <code>Http2_Core.Hpack.Huffman.Decode</code> — 1/1 subprograms · 7/7 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Read_Bit` | 7/7 |

</details>

<details>
<summary>🟢 <code>Http2_Core.Hpack.Int_Codec</code> — 2/2 subprograms · 31/31 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Decode` | 8/8 |
| 🟢 | `Encode` | 23/23 |

</details>

<details>
<summary>🟢 <code>Http2_Core.Hpack.Static_Table</code> — 4/4 subprograms · 61/61 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Find` | 4/4 |
| 🟢 | `Get_Name` | 18/18 |
| 🟢 | `Get_Value` | 18/18 |
| 🟢 | `Make` | 21/21 |

</details>

<details>
<summary>🟡 <code>Http2_Core.Hpack.String_Literal</code> — 2/4 subprograms · 24/35 VCs (69%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Huffman` | 1/1 |
| 🟢 | `To_Int_Codec` | 1/1 |
| 🟡 | `Decode` | 10/17 |
| 🟡 | `Encode_Raw` | 12/16 |

</details>

<details>
<summary>🟡 <code>Http2_Core.Hpack_Dynamic_Table</code> — 0/4 subprograms · 58/74 VCs (78%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟡 | `Add` | 31/39 |
| 🟡 | `Find` | 3/5 |
| 🟡 | `Lookup` | 19/23 |
| 🟡 | `Set_Max_Size` | 5/7 |

</details>

<details>
<summary>🟡 <code>Http2_Core.Wire</code> — 18/20 subprograms · 315/327 VCs (96%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Decode_Frame_Header` | 9/9 |
| 🟢 | `Decode_Window_Update_Payload` | 4/4 |
| 🟢 | `Encode_Continuation` | 31/31 |
| 🟢 | `Encode_Data` | 31/31 |
| 🟢 | `Encode_Goaway` | 40/40 |
| 🟢 | `Encode_Headers` | 32/32 |
| 🟢 | `Encode_Ping` | 23/23 |
| 🟢 | `Encode_Rst_Stream` | 10/10 |
| 🟢 | `Encode_Settings_Ack` | 6/6 |
| 🟢 | `Encode_Window_Update` | 10/10 |
| 🟢 | `Get_Be16` | 5/5 |
| 🟢 | `Get_Be24` | 7/7 |
| 🟢 | `Get_Be32` | 9/9 |
| 🟢 | `Put_Be16` | 13/13 |
| 🟢 | `Put_Be24` | 19/19 |
| 🟢 | `Put_Be32` | 25/25 |
| 🟢 | `Put_Header` | 17/17 |
| 🟢 | `Put_U8` | 5/5 |
| 🟡 | `Decode_Settings_Payload` | 8/15 |
| 🟡 | `Encode_Settings` | 11/16 |

</details>

</details>

<details>
<summary>🟡 <b>mqtt_core</b> — 4/39 subprograms · 656/755 VCs (87%)</summary>

<details>
<summary>🟡 <code>Mqtt_Core.Topics</code> — 0/1 subprograms · 4/13 VCs (31%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟡 | `Matches` | 4/13 |

</details>

<details>
<summary>🟡 <code>Mqtt_Core.Wire</code> — 4/38 subprograms · 652/742 VCs (88%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Decode_Suback_Single` | 3/3 |
| 🟢 | `Make_Subscription` | 8/8 |
| 🟢 | `Make_Topic_Filter` | 8/8 |
| 🟢 | `Peek_Packet_Type` | 4/4 |
| 🟡 | `Decode_Connack` | 13/14 |
| 🟡 | `Decode_Connect` | 65/71 |
| 🟡 | `Decode_Pingresp` | 11/12 |
| 🟡 | `Decode_Puback` | 12/13 |
| 🟡 | `Decode_Pubcomp` | 12/13 |
| 🟡 | `Decode_Publish` | 37/43 |
| 🟡 | `Decode_Publish_Header` | 13/14 |
| 🟡 | `Decode_Pubrec` | 12/13 |
| 🟡 | `Decode_Pubrel` | 12/13 |
| 🟡 | `Decode_Suback` | 24/32 |
| 🟡 | `Decode_Subscribe` | 41/43 |
| 🟡 | `Decode_Subscribe_Filters` | 43/49 |
| 🟡 | `Decode_Unsuback` | 12/13 |
| 🟡 | `Decode_Unsubscribe_Pid` | 12/13 |
| 🟡 | `Encode_Connack` | 15/16 |
| 🟡 | `Encode_Connect` | 38/44 |
| 🟡 | `Encode_Disconnect` | 12/13 |
| 🟡 | `Encode_Pingreq` | 12/13 |
| 🟡 | `Encode_Pingresp` | 12/13 |
| 🟡 | `Encode_Puback` | 13/14 |
| 🟡 | `Encode_Pubcomp` | 13/14 |
| 🟡 | `Encode_Publish_Qos0` | 20/21 |
| 🟡 | `Encode_Publish_Qos1` | 21/22 |
| 🟡 | `Encode_Publish_Qos2` | 21/22 |
| 🟡 | `Encode_Pubrec` | 13/14 |
| 🟡 | `Encode_Pubrel` | 13/14 |
| 🟡 | `Encode_Suback` | 18/22 |
| 🟡 | `Encode_Suback_Single` | 20/21 |
| 🟡 | `Encode_Subscribe` | 25/37 |
| 🟡 | `Encode_Subscribe_Single` | 3/4 |
| 🟡 | `Encode_Unsuback` | 13/14 |
| 🟡 | `Encode_Unsubscribe` | 22/35 |
| 🟡 | `Encode_Unsubscribe_Single` | 2/4 |
| 🟡 | `To_Bytes` | 4/6 |

</details>

</details>

<details>
<summary>🟢 <b>grpc_core</b> — 4/4 subprograms · 96/96 VCs (100%)</summary>

<details>
<summary>🟢 <code>Grpc_Core.Framing</code> — 2/2 subprograms · 69/69 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Decode` | 29/29 |
| 🟢 | `Encode` | 40/40 |

</details>

<details>
<summary>🟢 <code>Grpc_Core.Status</code> — 2/2 subprograms · 27/27 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `From_String` | 13/13 |
| 🟢 | `To_String` | 14/14 |

</details>

</details>

<details>
<summary>🟡 <b>rflx</b> — 3111/3184 subprograms · 23,963/24,032 VCs (100%)</summary>

<details>
<summary>🟢 <code>RFLX.Certificate</code> — 4/4 subprograms · 4/4 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟡 <code>RFLX.Certificate.Cert_Entry</code> — 60/62 subprograms · 538/540 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Cert_Data` | 2/2 |
| 🟢 | `Field_First_Cert_Data_Len` | 2/2 |
| 🟢 | `Field_First_Ext_Len` | 5/5 |
| 🟢 | `Field_First_Extensions` | 6/6 |
| 🟢 | `Field_First_Internal` | 7/7 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Field_Size_Internal` | 4/4 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Cert_Data` | 6/6 |
| 🟢 | `Get_Cert_Data` | 16/16 |
| 🟢 | `Get_Cert_Data_Len` | 1/1 |
| 🟢 | `Get_Ext_Len` | 1/1 |
| 🟢 | `Get_Extensions` | 6/6 |
| 🟢 | `Get_Extensions` | 16/16 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Cert_Data` | 9/9 |
| 🟢 | `Initialize_Cert_Data_Private` | 19/19 |
| 🟢 | `Initialize_Extensions` | 13/13 |
| 🟢 | `Initialize_Extensions_Private` | 21/21 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 35/35 |
| 🟢 | `Set_Cert_Data` | 34/34 |
| 🟢 | `Set_Cert_Data_Empty` | 10/10 |
| 🟢 | `Set_Extensions` | 38/38 |
| 🟢 | `Set_Extensions_Empty` | 14/14 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 15/15 |
| 🟢 | `To_Structure` | 16/16 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 13/13 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 24/24 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Cert_Data_Len` | 7/8 |
| 🟡 | `Set_Ext_Len` | 9/10 |

</details>

<details>
<summary>🟢 <code>RFLX.Certificate.Cert_Entry_List</code> — 13/13 subprograms · 96/96 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Append_Element` | 11/11 |
| 🟢 | `Available_Space` | 1/1 |
| 🟢 | `Context` | 2/2 |
| 🟢 | `Contextpredicate` | 5/5 |
| 🟢 | `Copy` | 9/9 |
| 🟢 | `Data` | 9/9 |
| 🟢 | `Initialize` | 11/11 |
| 🟢 | `Initialize` | 17/17 |
| 🟢 | `Reset` | 3/3 |
| 🟢 | `Size` | 1/1 |
| 🟢 | `Switch` | 7/7 |
| 🟢 | `Take_Buffer` | 6/6 |
| 🟢 | `Update` | 14/14 |

</details>

<details>
<summary>🟡 <code>RFLX.Certificate.Message</code> — 59/60 subprograms · 511/512 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Complete_Cert_List` | 1/1 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Cert_List` | 6/6 |
| 🟢 | `Field_First_Cert_List_Len` | 5/5 |
| 🟢 | `Field_First_Context` | 2/2 |
| 🟢 | `Field_First_Context_Len` | 2/2 |
| 🟢 | `Field_First_Internal` | 7/7 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Field_Size_Internal` | 4/4 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Cert_List_Len` | 1/1 |
| 🟢 | `Get_Context` | 6/6 |
| 🟢 | `Get_Context` | 16/16 |
| 🟢 | `Get_Context_Len` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Cert_List` | 13/13 |
| 🟢 | `Initialize_Cert_List_Private` | 21/21 |
| 🟢 | `Initialize_Context` | 9/9 |
| 🟢 | `Initialize_Context_Private` | 19/19 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 35/35 |
| 🟢 | `Set_Cert_List` | 20/20 |
| 🟢 | `Set_Cert_List_Empty` | 14/14 |
| 🟢 | `Set_Context` | 34/34 |
| 🟢 | `Set_Context_Empty` | 10/10 |
| 🟢 | `Set_Context_Len` | 8/8 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Switch_To_Cert_List` | 26/26 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `Update_Cert_List` | 17/17 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 13/13 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 24/24 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Cert_List_Len` | 9/10 |

</details>

<details>
<summary>🟢 <code>RFLX.Certificate_Verify</code> — 2/2 subprograms · 2/2 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟡 <code>RFLX.Certificate_Verify.Message</code> — 53/55 subprograms · 421/423 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Algorithm` | 2/2 |
| 🟢 | `Field_First_Internal` | 6/6 |
| 🟢 | `Field_First_Sig_Len` | 2/2 |
| 🟢 | `Field_First_Signature` | 2/2 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Field_Size_Internal` | 3/3 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Algorithm` | 1/1 |
| 🟢 | `Get_Sig_Len` | 1/1 |
| 🟢 | `Get_Signature` | 6/6 |
| 🟢 | `Get_Signature` | 16/16 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Signature` | 13/13 |
| 🟢 | `Initialize_Signature_Private` | 21/21 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 35/35 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Set_Signature` | 38/38 |
| 🟢 | `Set_Signature_Empty` | 14/14 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 10/10 |
| 🟢 | `To_Structure` | 10/10 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 12/12 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 24/24 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Algorithm` | 7/8 |
| 🟡 | `Set_Sig_Len` | 9/10 |

</details>

<details>
<summary>🟢 <code>RFLX.Client_Hello</code> — 5/5 subprograms · 5/5 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟡 <code>RFLX.Client_Hello.Message</code> — 83/86 subprograms · 843/846 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Complete_Extensions` | 1/1 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Cipher_Suites` | 6/6 |
| 🟢 | `Field_First_Compression_Len` | 5/5 |
| 🟢 | `Field_First_Compression_Methods` | 6/6 |
| 🟢 | `Field_First_Extensions` | 6/6 |
| 🟢 | `Field_First_Extensions_Len` | 5/5 |
| 🟢 | `Field_First_Internal` | 13/13 |
| 🟢 | `Field_First_Legacy_Version_Field` | 2/2 |
| 🟢 | `Field_First_Random` | 2/2 |
| 🟢 | `Field_First_Session_Id` | 2/2 |
| 🟢 | `Field_First_Session_Id_Len` | 2/2 |
| 🟢 | `Field_First_Suites_Len` | 5/5 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Field_Size_Internal` | 6/6 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Cipher_Suites` | 6/6 |
| 🟢 | `Get_Cipher_Suites` | 16/16 |
| 🟢 | `Get_Compression_Len` | 1/1 |
| 🟢 | `Get_Compression_Methods` | 6/6 |
| 🟢 | `Get_Compression_Methods` | 16/16 |
| 🟢 | `Get_Extensions_Len` | 1/1 |
| 🟢 | `Get_Legacy_Version_Field` | 1/1 |
| 🟢 | `Get_Random` | 6/6 |
| 🟢 | `Get_Random` | 16/16 |
| 🟢 | `Get_Session_Id` | 6/6 |
| 🟢 | `Get_Session_Id` | 16/16 |
| 🟢 | `Get_Session_Id_Len` | 1/1 |
| 🟢 | `Get_Suites_Len` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Cipher_Suites` | 11/11 |
| 🟢 | `Initialize_Cipher_Suites_Private` | 21/21 |
| 🟢 | `Initialize_Compression_Methods` | 13/13 |
| 🟢 | `Initialize_Compression_Methods_Private` | 23/23 |
| 🟢 | `Initialize_Extensions` | 17/17 |
| 🟢 | `Initialize_Extensions_Private` | 25/25 |
| 🟢 | `Initialize_Random` | 7/7 |
| 🟢 | `Initialize_Random_Private` | 17/17 |
| 🟢 | `Initialize_Session_Id` | 9/9 |
| 🟢 | `Initialize_Session_Id_Private` | 19/19 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 35/35 |
| 🟢 | `Set_Cipher_Suites` | 36/36 |
| 🟢 | `Set_Compression_Len` | 12/12 |
| 🟢 | `Set_Compression_Methods` | 38/38 |
| 🟢 | `Set_Extensions` | 24/24 |
| 🟢 | `Set_Random` | 32/32 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Set_Session_Id` | 34/34 |
| 🟢 | `Set_Session_Id_Empty` | 10/10 |
| 🟢 | `Set_Session_Id_Len` | 8/8 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Switch_To_Extensions` | 26/26 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `Update_Extensions` | 17/17 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 15/15 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 24/24 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Extensions_Len` | 13/14 |
| 🟡 | `Set_Legacy_Version_Field` | 6/7 |
| 🟡 | `Set_Suites_Len` | 9/10 |

</details>

<details>
<summary>🟢 <code>RFLX.Connack</code> — 3/3 subprograms · 3/3 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟢 <code>RFLX.Connack.Packet</code> — 59/59 subprograms · 341/341 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Internal` | 9/9 |
| 🟢 | `Field_First_Packet_Type` | 2/2 |
| 🟢 | `Field_First_Remaining_Length` | 2/2 |
| 🟢 | `Field_First_Reserved` | 2/2 |
| 🟢 | `Field_First_Reserved_Ack_Flags` | 2/2 |
| 🟢 | `Field_First_Return_Code` | 2/2 |
| 🟢 | `Field_First_Session_Present` | 2/2 |
| 🟢 | `Field_Last` | 4/4 |
| 🟢 | `Field_Size` | 2/2 |
| 🟢 | `Field_Size_Internal` | 2/2 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Packet_Type` | 1/1 |
| 🟢 | `Get_Remaining_Length` | 1/1 |
| 🟢 | `Get_Reserved` | 1/1 |
| 🟢 | `Get_Reserved_Ack_Flags` | 1/1 |
| 🟢 | `Get_Return_Code` | 1/1 |
| 🟢 | `Get_Session_Present` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 34/34 |
| 🟢 | `Set_Packet_Type` | 9/9 |
| 🟢 | `Set_Remaining_Length` | 9/9 |
| 🟢 | `Set_Reserved` | 9/9 |
| 🟢 | `Set_Reserved_Ack_Flags` | 9/9 |
| 🟢 | `Set_Return_Code` | 14/14 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Set_Session_Present` | 10/10 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 9/9 |
| 🟢 | `To_Structure` | 8/8 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 11/11 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 21/21 |
| 🟢 | `Verify_Message` | 4/4 |

</details>

<details>
<summary>🟢 <code>RFLX.Connect</code> — 9/9 subprograms · 9/9 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟡 <code>RFLX.Connect.Packet</code> — 129/136 subprograms · 1,812/1,819 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 10/10 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Clean_Session` | 6/6 |
| 🟢 | `Field_First_Client_Id` | 6/6 |
| 🟢 | `Field_First_Client_Id_Length` | 6/6 |
| 🟢 | `Field_First_Internal` | 27/27 |
| 🟢 | `Field_First_Keep_Alive` | 6/6 |
| 🟢 | `Field_First_Packet_Type` | 2/2 |
| 🟢 | `Field_First_Password` | 6/6 |
| 🟢 | `Field_First_Password_Flag` | 6/6 |
| 🟢 | `Field_First_Password_Length` | 5/5 |
| 🟢 | `Field_First_Protocol_Level` | 5/5 |
| 🟢 | `Field_First_Protocol_Name` | 2/2 |
| 🟢 | `Field_First_Protocol_Name_Length` | 2/2 |
| 🟢 | `Field_First_Remaining_Length` | 2/2 |
| 🟢 | `Field_First_Reserved` | 2/2 |
| 🟢 | `Field_First_Reserved_Connect_Flag` | 6/6 |
| 🟢 | `Field_First_User_Name` | 4/4 |
| 🟢 | `Field_First_User_Name_Flag` | 6/6 |
| 🟢 | `Field_First_User_Name_Length` | 11/11 |
| 🟢 | `Field_First_Will_Flag` | 6/6 |
| 🟢 | `Field_First_Will_Message` | 6/6 |
| 🟢 | `Field_First_Will_Message_Length` | 5/5 |
| 🟢 | `Field_First_Will_QoS` | 6/6 |
| 🟢 | `Field_First_Will_Retain` | 6/6 |
| 🟢 | `Field_First_Will_Topic` | 6/6 |
| 🟢 | `Field_First_Will_Topic_Length` | 5/5 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Field_Size_Internal` | 8/8 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Clean_Session` | 1/1 |
| 🟢 | `Get_Client_Id` | 6/6 |
| 🟢 | `Get_Client_Id` | 16/16 |
| 🟢 | `Get_Client_Id_Length` | 1/1 |
| 🟢 | `Get_Keep_Alive` | 1/1 |
| 🟢 | `Get_Packet_Type` | 1/1 |
| 🟢 | `Get_Password` | 6/6 |
| 🟢 | `Get_Password` | 16/16 |
| 🟢 | `Get_Password_Flag` | 1/1 |
| 🟢 | `Get_Password_Length` | 1/1 |
| 🟢 | `Get_Protocol_Level` | 1/1 |
| 🟢 | `Get_Protocol_Name` | 6/6 |
| 🟢 | `Get_Protocol_Name` | 16/16 |
| 🟢 | `Get_Protocol_Name_Length` | 1/1 |
| 🟢 | `Get_Remaining_Length` | 1/1 |
| 🟢 | `Get_Reserved` | 1/1 |
| 🟢 | `Get_Reserved_Connect_Flag` | 1/1 |
| 🟢 | `Get_User_Name` | 6/6 |
| 🟢 | `Get_User_Name` | 16/16 |
| 🟢 | `Get_User_Name_Flag` | 1/1 |
| 🟢 | `Get_User_Name_Length` | 1/1 |
| 🟢 | `Get_Will_Flag` | 1/1 |
| 🟢 | `Get_Will_Message` | 6/6 |
| 🟢 | `Get_Will_Message` | 16/16 |
| 🟢 | `Get_Will_Message_Length` | 1/1 |
| 🟢 | `Get_Will_QoS` | 1/1 |
| 🟢 | `Get_Will_Retain` | 1/1 |
| 🟢 | `Get_Will_Topic` | 6/6 |
| 🟢 | `Get_Will_Topic` | 16/16 |
| 🟢 | `Get_Will_Topic_Length` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Client_Id` | 32/32 |
| 🟢 | `Initialize_Client_Id_Private` | 40/40 |
| 🟢 | `Initialize_Password` | 33/33 |
| 🟢 | `Initialize_Password_Private` | 41/41 |
| 🟢 | `Initialize_Protocol_Name` | 11/11 |
| 🟢 | `Initialize_Protocol_Name_Private` | 21/21 |
| 🟢 | `Initialize_User_Name` | 32/32 |
| 🟢 | `Initialize_User_Name_Private` | 40/40 |
| 🟢 | `Initialize_Will_Message` | 34/34 |
| 🟢 | `Initialize_Will_Message_Private` | 42/42 |
| 🟢 | `Initialize_Will_Topic` | 29/29 |
| 🟢 | `Initialize_Will_Topic_Private` | 39/39 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Set` | 35/35 |
| 🟢 | `Set_Clean_Session` | 22/22 |
| 🟢 | `Set_Client_Id` | 57/57 |
| 🟢 | `Set_Client_Id_Empty` | 33/33 |
| 🟢 | `Set_Packet_Type` | 9/9 |
| 🟢 | `Set_Password` | 58/58 |
| 🟢 | `Set_Password_Empty` | 34/34 |
| 🟢 | `Set_Password_Flag` | 14/14 |
| 🟢 | `Set_Protocol_Level` | 11/11 |
| 🟢 | `Set_Protocol_Name` | 36/36 |
| 🟢 | `Set_Protocol_Name_Length` | 11/11 |
| 🟢 | `Set_Remaining_Length` | 10/10 |
| 🟢 | `Set_Reserved` | 9/9 |
| 🟢 | `Set_Reserved_Connect_Flag` | 23/23 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Set_User_Name` | 57/57 |
| 🟢 | `Set_User_Name_Empty` | 33/33 |
| 🟢 | `Set_User_Name_Flag` | 12/12 |
| 🟢 | `Set_Will_Flag` | 20/20 |
| 🟢 | `Set_Will_Message` | 59/59 |
| 🟢 | `Set_Will_Message_Empty` | 35/35 |
| 🟢 | `Set_Will_QoS` | 18/18 |
| 🟢 | `Set_Will_Retain` | 16/16 |
| 🟢 | `Set_Will_Topic` | 54/54 |
| 🟢 | `Set_Will_Topic_Empty` | 30/30 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 19/19 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Message` | 5/5 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 5/5 |
| 🟢 | `Valid_Predecessors_Invariant` | 4/4 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 24/24 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟢 | `Well_Formed_Message` | 5/5 |
| 🟡 | `Reset_Dependent_Fields` | 13/14 |
| 🟡 | `Set_Client_Id_Length` | 25/26 |
| 🟡 | `Set_Keep_Alive` | 23/24 |
| 🟡 | `Set_Password_Length` | 29/30 |
| 🟡 | `Set_User_Name_Length` | 27/28 |
| 🟡 | `Set_Will_Message_Length` | 29/30 |
| 🟡 | `Set_Will_Topic_Length` | 27/28 |

</details>

<details>
<summary>🟢 <code>RFLX.Control_Packet</code> — 5/5 subprograms · 5/5 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟢 <code>RFLX.Control_Packet.Incoming_Packet</code> — 58/58 subprograms · 449/449 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Flags` | 2/2 |
| 🟢 | `Field_First_Internal` | 7/7 |
| 🟢 | `Field_First_Packet_Type` | 2/2 |
| 🟢 | `Field_First_Payload` | 2/2 |
| 🟢 | `Field_First_Remaining_Length` | 2/2 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Field_Size_Internal` | 3/3 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Flags` | 1/1 |
| 🟢 | `Get_Packet_Type` | 1/1 |
| 🟢 | `Get_Payload` | 6/6 |
| 🟢 | `Get_Payload` | 16/16 |
| 🟢 | `Get_Remaining_Length` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Payload` | 15/15 |
| 🟢 | `Initialize_Payload_Private` | 23/23 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 35/35 |
| 🟢 | `Set_Flags` | 10/10 |
| 🟢 | `Set_Packet_Type` | 8/8 |
| 🟢 | `Set_Payload` | 40/40 |
| 🟢 | `Set_Payload_Empty` | 16/16 |
| 🟢 | `Set_Remaining_Length` | 12/12 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 11/11 |
| 🟢 | `To_Structure` | 11/11 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 12/12 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 24/24 |
| 🟢 | `Verify_Message` | 4/4 |

</details>

<details>
<summary>🟢 <code>RFLX.Control_Packet.Remaining_Length</code> — 64/64 subprograms · 424/424 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Field_Condition` | 9/9 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Continuation_1` | 2/2 |
| 🟢 | `Field_First_Continuation_2` | 2/2 |
| 🟢 | `Field_First_Continuation_3` | 2/2 |
| 🟢 | `Field_First_Continuation_4` | 2/2 |
| 🟢 | `Field_First_Internal` | 11/11 |
| 🟢 | `Field_First_Value_1` | 2/2 |
| 🟢 | `Field_First_Value_2` | 2/2 |
| 🟢 | `Field_First_Value_3` | 2/2 |
| 🟢 | `Field_First_Value_4` | 2/2 |
| 🟢 | `Field_Last` | 4/4 |
| 🟢 | `Field_Size` | 2/2 |
| 🟢 | `Field_Size_Internal` | 2/2 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Continuation_1` | 1/1 |
| 🟢 | `Get_Continuation_2` | 1/1 |
| 🟢 | `Get_Continuation_3` | 1/1 |
| 🟢 | `Get_Continuation_4` | 1/1 |
| 🟢 | `Get_Value_1` | 1/1 |
| 🟢 | `Get_Value_2` | 1/1 |
| 🟢 | `Get_Value_3` | 1/1 |
| 🟢 | `Get_Value_4` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 34/34 |
| 🟢 | `Set_Continuation_1` | 8/8 |
| 🟢 | `Set_Continuation_2` | 12/12 |
| 🟢 | `Set_Continuation_3` | 16/16 |
| 🟢 | `Set_Continuation_4` | 21/21 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Set_Value_1` | 13/13 |
| 🟢 | `Set_Value_2` | 17/17 |
| 🟢 | `Set_Value_3` | 21/21 |
| 🟢 | `Set_Value_4` | 24/24 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 11/11 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Message` | 3/3 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 6/6 |
| 🟢 | `Valid_Predecessors_Invariant` | 5/5 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 21/21 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟢 | `Well_Formed_Message` | 3/3 |

</details>

<details>
<summary>🟡 <code>RFLX.Control_Packet.UTF8_String</code> — 51/52 subprograms · 398/399 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Data` | 2/2 |
| 🟢 | `Field_First_Internal` | 5/5 |
| 🟢 | `Field_First_Length` | 2/2 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Field_Size_Internal` | 3/3 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Data` | 6/6 |
| 🟢 | `Get_Data` | 16/16 |
| 🟢 | `Get_Length` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Data` | 11/11 |
| 🟢 | `Initialize_Data_Private` | 19/19 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 35/35 |
| 🟢 | `Set_Data` | 36/36 |
| 🟢 | `Set_Data_Empty` | 12/12 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 9/9 |
| 🟢 | `To_Structure` | 9/9 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 12/12 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 24/24 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Length` | 7/8 |

</details>

<details>
<summary>🟢 <code>RFLX.Disconnect</code> — 2/2 subprograms · 2/2 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟢 <code>RFLX.Disconnect.Packet</code> — 50/50 subprograms · 292/292 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Internal` | 6/6 |
| 🟢 | `Field_First_Packet_Type` | 2/2 |
| 🟢 | `Field_First_Remaining_Length` | 2/2 |
| 🟢 | `Field_First_Reserved` | 2/2 |
| 🟢 | `Field_Last` | 4/4 |
| 🟢 | `Field_Size` | 2/2 |
| 🟢 | `Field_Size_Internal` | 2/2 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Packet_Type` | 1/1 |
| 🟢 | `Get_Remaining_Length` | 1/1 |
| 🟢 | `Get_Reserved` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 34/34 |
| 🟢 | `Set_Packet_Type` | 9/9 |
| 🟢 | `Set_Remaining_Length` | 11/11 |
| 🟢 | `Set_Reserved` | 9/9 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 6/6 |
| 🟢 | `To_Structure` | 5/5 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 11/11 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 21/21 |
| 🟢 | `Verify_Message` | 4/4 |

</details>

<details>
<summary>🟢 <code>RFLX.Flow_Gate</code> — 1/1 subprograms · 1/1 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟡 <code>RFLX.Flow_Gate.Decision_Packet</code> — 46/47 subprograms · 276/277 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Bytes` | 2/2 |
| 🟢 | `Field_First_Internal` | 5/5 |
| 🟢 | `Field_First_Kind` | 2/2 |
| 🟢 | `Field_Last` | 4/4 |
| 🟢 | `Field_Size` | 2/2 |
| 🟢 | `Field_Size_Internal` | 2/2 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Bytes` | 1/1 |
| 🟢 | `Get_Kind` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 34/34 |
| 🟢 | `Set_Kind` | 8/8 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 5/5 |
| 🟢 | `To_Structure` | 4/4 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 11/11 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 21/21 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Bytes` | 11/12 |

</details>

<details>
<summary>🟡 <code>RFLX.Flow_Gate.Op_Packet</code> — 46/47 subprograms · 276/277 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Bytes` | 2/2 |
| 🟢 | `Field_First_Internal` | 5/5 |
| 🟢 | `Field_First_Kind` | 2/2 |
| 🟢 | `Field_Last` | 4/4 |
| 🟢 | `Field_Size` | 2/2 |
| 🟢 | `Field_Size_Internal` | 2/2 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Bytes` | 1/1 |
| 🟢 | `Get_Kind` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 34/34 |
| 🟢 | `Set_Kind` | 8/8 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 5/5 |
| 🟢 | `To_Structure` | 4/4 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 11/11 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 21/21 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Bytes` | 11/12 |

</details>

<details>
<summary>🟢 <code>RFLX.Flow_Gate.Send_Gate.FSM</code> — 23/23 subprograms · 211/211 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Apply_Conn` | 14/14 |
| 🟢 | `Apply_Stream` | 14/14 |
| 🟢 | `Approve_Send` | 26/26 |
| 🟢 | `Bump_Conn_OK` | 7/7 |
| 🟢 | `Bump_Stream_OK` | 7/7 |
| 🟢 | `Check_Send` | 7/7 |
| 🟢 | `Deny_Send` | 14/14 |
| 🟢 | `Dispatch` | 11/11 |
| 🟢 | `Emit_Decision` | 3/3 |
| 🟢 | `Finalize` | 17/17 |
| 🟢 | `Flow_Error` | 14/14 |
| 🟢 | `Has_Data` | 1/1 |
| 🟢 | `Idle` | 5/5 |
| 🟢 | `Init_Stream_Window` | 5/5 |
| 🟢 | `Initialize` | 12/12 |
| 🟢 | `Private_Context` | 8/8 |
| 🟢 | `Read` | 10/10 |
| 🟢 | `Read_Buffer_Size` | 3/3 |
| 🟢 | `Reset_Messages_Before_Write` | 2/2 |
| 🟢 | `Run` | 5/5 |
| 🟢 | `Tick` | 14/14 |
| 🟢 | `Write` | 9/9 |
| 🟢 | `Write_Buffer_Size` | 3/3 |

</details>

<details>
<summary>🟢 <code>RFLX.Flow_Gate.Send_Gate.FSM.Read</code> — 2/2 subprograms · 21/21 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Read` | 20/20 |
| 🟢 | `Read_Pre` | 1/1 |

</details>

<details>
<summary>🟢 <code>RFLX.Flow_Gate.Send_Gate.FSM.Read.FLOW_GATE_DECISION_PACKET_READGP53292</code> — 1/1 subprograms · 6/6 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Flow_Gate_Decision_Packet_Read` | 6/6 |

</details>

<details>
<summary>🟢 <code>RFLX.Flow_Gate.Send_Gate.FSM.Write</code> — 2/2 subprograms · 24/24 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Write` | 20/20 |
| 🟢 | `Write_Pre` | 4/4 |

</details>

<details>
<summary>🟢 <code>RFLX.Flow_Gate.Send_Gate.FSM.Write.FLOW_GATE_OP_PACKET_WRITEGP55267</code> — 1/1 subprograms · 22/22 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Flow_Gate_Op_Packet_Write` | 22/22 |

</details>

<details>
<summary>🟢 <code>RFLX.Flow_Gate.Send_Gate.FSM_Allocator</code> — 1/3 subprograms · 2/2 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `SLOT_PTR_TYPE_4096PREDICATE` | 2/2 |
| ⚪ | `Finalize` | — |
| ⚪ | `Initialize` | — |

</details>

<details>
<summary>🟢 <code>RFLX.Frame</code> — 4/4 subprograms · 4/4 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟡 <code>RFLX.Frame.Packet</code> — 63/65 subprograms · 505/507 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Flags` | 2/2 |
| 🟢 | `Field_First_Frame_Type` | 2/2 |
| 🟢 | `Field_First_Internal` | 9/9 |
| 🟢 | `Field_First_Length` | 2/2 |
| 🟢 | `Field_First_Payload` | 2/2 |
| 🟢 | `Field_First_Reserved` | 2/2 |
| 🟢 | `Field_First_Stream_Identifier` | 2/2 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Field_Size_Internal` | 3/3 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Flags` | 1/1 |
| 🟢 | `Get_Frame_Type` | 1/1 |
| 🟢 | `Get_Length` | 1/1 |
| 🟢 | `Get_Payload` | 6/6 |
| 🟢 | `Get_Payload` | 16/16 |
| 🟢 | `Get_Reserved` | 1/1 |
| 🟢 | `Get_Stream_Identifier` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Payload` | 17/17 |
| 🟢 | `Initialize_Payload_Private` | 25/25 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 35/35 |
| 🟢 | `Set_Flags` | 12/12 |
| 🟢 | `Set_Frame_Type` | 10/10 |
| 🟢 | `Set_Frame_Type` | 10/10 |
| 🟢 | `Set_Payload` | 42/42 |
| 🟢 | `Set_Payload_Empty` | 18/18 |
| 🟢 | `Set_Reserved` | 13/13 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 13/13 |
| 🟢 | `To_Structure` | 14/14 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 12/12 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 24/24 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Length` | 7/8 |
| 🟡 | `Set_Stream_Identifier` | 13/14 |

</details>

<details>
<summary>🟢 <code>RFLX.Goaway</code> — 3/3 subprograms · 3/3 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟡 <code>RFLX.Goaway.Packet</code> — 53/55 subprograms · 410/412 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Additional_Debug_Data` | 2/2 |
| 🟢 | `Field_First_Error_Code` | 2/2 |
| 🟢 | `Field_First_Internal` | 7/7 |
| 🟢 | `Field_First_Last_Stream_Id` | 2/2 |
| 🟢 | `Field_First_Reserved` | 2/2 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Field_Size_Internal` | 2/2 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Additional_Debug_Data` | 6/6 |
| 🟢 | `Get_Additional_Debug_Data` | 16/16 |
| 🟢 | `Get_Error_Code` | 1/1 |
| 🟢 | `Get_Last_Stream_Id` | 1/1 |
| 🟢 | `Get_Reserved` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Additional_Debug_Data` | 13/13 |
| 🟢 | `Initialize_Additional_Debug_Data_Private` | 21/21 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 35/35 |
| 🟢 | `Set_Additional_Debug_Data` | 38/38 |
| 🟢 | `Set_Additional_Debug_Data_Empty` | 14/14 |
| 🟢 | `Set_Reserved` | 7/7 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 11/11 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 2/2 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 24/24 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Error_Code` | 9/10 |
| 🟡 | `Set_Last_Stream_Id` | 7/8 |

</details>

<details>
<summary>🟢 <code>RFLX.Handshake_Layer</code> — 1/1 subprograms · 1/1 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟡 <code>RFLX.Handshake_Layer.Envelope</code> — 54/55 subprograms · 422/423 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Body_Bytes` | 2/2 |
| 🟢 | `Field_First_Internal` | 6/6 |
| 🟢 | `Field_First_Length` | 2/2 |
| 🟢 | `Field_First_Msg_Type` | 2/2 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Field_Size_Internal` | 3/3 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Body_Bytes` | 6/6 |
| 🟢 | `Get_Body_Bytes` | 16/16 |
| 🟢 | `Get_Length` | 1/1 |
| 🟢 | `Get_Msg_Type` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Body_Bytes` | 13/13 |
| 🟢 | `Initialize_Body_Bytes_Private` | 21/21 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 35/35 |
| 🟢 | `Set_Body_Bytes` | 38/38 |
| 🟢 | `Set_Body_Bytes_Empty` | 14/14 |
| 🟢 | `Set_Msg_Type` | 8/8 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 10/10 |
| 🟢 | `To_Structure` | 10/10 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 12/12 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 24/24 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Length` | 9/10 |

</details>

<details>
<summary>🟡 <code>RFLX.Headers.Packet</code> — 38/44 subprograms · 316/322 VCs (98%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Field_Block_Fragment` | 2/2 |
| 🟢 | `Field_First_Internal` | 4/4 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Field_Block_Fragment` | 9/9 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 35/35 |
| 🟢 | `Set_Field_Block_Fragment_Empty` | 10/10 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 12/12 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 17/17 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Data` | 5/6 |
| 🟡 | `Field_Size_Internal` | 2/3 |
| 🟡 | `Get_Field_Block_Fragment` | 5/6 |
| 🟡 | `Get_Field_Block_Fragment` | 15/16 |
| 🟡 | `Initialize_Field_Block_Fragment_Private` | 16/17 |
| 🟡 | `Set_Field_Block_Fragment` | 33/34 |

</details>

<details>
<summary>🟢 <code>RFLX.Hkdf</code> — 3/3 subprograms · 3/3 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟡 <code>RFLX.Hkdf.Label</code> — 63/64 subprograms · 561/562 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Context_Bytes` | 6/6 |
| 🟢 | `Field_First_Context_Len` | 5/5 |
| 🟢 | `Field_First_Internal` | 8/8 |
| 🟢 | `Field_First_Label_Bytes` | 2/2 |
| 🟢 | `Field_First_Label_Len` | 2/2 |
| 🟢 | `Field_First_Length` | 2/2 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Field_Size_Internal` | 4/4 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Context_Bytes` | 6/6 |
| 🟢 | `Get_Context_Bytes` | 16/16 |
| 🟢 | `Get_Context_Len` | 1/1 |
| 🟢 | `Get_Label_Bytes` | 6/6 |
| 🟢 | `Get_Label_Bytes` | 16/16 |
| 🟢 | `Get_Label_Len` | 1/1 |
| 🟢 | `Get_Length` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Context_Bytes` | 15/15 |
| 🟢 | `Initialize_Context_Bytes_Private` | 23/23 |
| 🟢 | `Initialize_Label_Bytes` | 11/11 |
| 🟢 | `Initialize_Label_Bytes_Private` | 21/21 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 35/35 |
| 🟢 | `Set_Context_Bytes` | 40/40 |
| 🟢 | `Set_Context_Bytes_Empty` | 16/16 |
| 🟢 | `Set_Context_Len` | 12/12 |
| 🟢 | `Set_Label_Bytes` | 36/36 |
| 🟢 | `Set_Label_Len` | 10/10 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 16/16 |
| 🟢 | `To_Structure` | 17/17 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 13/13 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 24/24 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Length` | 7/8 |

</details>

<details>
<summary>🟢 <code>RFLX.Http2_Parameters</code> — 6/6 subprograms · 12/12 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Base_Integer` | 2/2 |
| 🟢 | `To_Base_Integer` | 2/2 |
| 🟢 | `To_Base_Integer` | 2/2 |
| 🟢 | `Valid_HTTP_2_Error_Code` | 2/2 |
| 🟢 | `Valid_HTTP_2_Frame_Type` | 2/2 |
| 🟢 | `Valid_HTTP_2_Settings` | 2/2 |

</details>

<details>
<summary>🟢 <code>RFLX.Key_Share</code> — 2/2 subprograms · 2/2 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟡 <code>RFLX.Key_Share.Client_Hello_Payload</code> — 51/52 subprograms · 398/399 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Client_Shares` | 2/2 |
| 🟢 | `Field_First_Client_Shares_Len` | 2/2 |
| 🟢 | `Field_First_Internal` | 5/5 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Field_Size_Internal` | 3/3 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Client_Shares` | 6/6 |
| 🟢 | `Get_Client_Shares` | 16/16 |
| 🟢 | `Get_Client_Shares_Len` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Client_Shares` | 11/11 |
| 🟢 | `Initialize_Client_Shares_Private` | 19/19 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 35/35 |
| 🟢 | `Set_Client_Shares` | 36/36 |
| 🟢 | `Set_Client_Shares_Empty` | 12/12 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 9/9 |
| 🟢 | `To_Structure` | 9/9 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 12/12 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 24/24 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Client_Shares_Len` | 7/8 |

</details>

<details>
<summary>🟡 <code>RFLX.Key_Share.Key_Share_Entry</code> — 53/54 subprograms · 408/409 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Group` | 2/2 |
| 🟢 | `Field_First_Internal` | 6/6 |
| 🟢 | `Field_First_Key_Exchange` | 2/2 |
| 🟢 | `Field_First_Key_Exchange_Len` | 2/2 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Field_Size_Internal` | 3/3 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Group` | 1/1 |
| 🟢 | `Get_Key_Exchange` | 6/6 |
| 🟢 | `Get_Key_Exchange` | 16/16 |
| 🟢 | `Get_Key_Exchange_Len` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Key_Exchange` | 13/13 |
| 🟢 | `Initialize_Key_Exchange_Private` | 21/21 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 35/35 |
| 🟢 | `Set_Group` | 8/8 |
| 🟢 | `Set_Key_Exchange` | 38/38 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 10/10 |
| 🟢 | `To_Structure` | 10/10 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 12/12 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 24/24 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Key_Exchange_Len` | 9/10 |

</details>

<details>
<summary>🟢 <code>RFLX.Key_Share.Key_Share_Entry_List</code> — 13/13 subprograms · 96/96 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Append_Element` | 11/11 |
| 🟢 | `Available_Space` | 1/1 |
| 🟢 | `Context` | 2/2 |
| 🟢 | `Contextpredicate` | 5/5 |
| 🟢 | `Copy` | 9/9 |
| 🟢 | `Data` | 9/9 |
| 🟢 | `Initialize` | 11/11 |
| 🟢 | `Initialize` | 17/17 |
| 🟢 | `Reset` | 3/3 |
| 🟢 | `Size` | 1/1 |
| 🟢 | `Switch` | 7/7 |
| 🟢 | `Take_Buffer` | 6/6 |
| 🟢 | `Update` | 14/14 |

</details>

<details>
<summary>🟡 <code>RFLX.Key_Share.Server_Hello_Payload</code> — 53/54 subprograms · 408/409 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Group` | 2/2 |
| 🟢 | `Field_First_Internal` | 6/6 |
| 🟢 | `Field_First_Key_Exchange` | 2/2 |
| 🟢 | `Field_First_Key_Exchange_Len` | 2/2 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Field_Size_Internal` | 3/3 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Group` | 1/1 |
| 🟢 | `Get_Key_Exchange` | 6/6 |
| 🟢 | `Get_Key_Exchange` | 16/16 |
| 🟢 | `Get_Key_Exchange_Len` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Key_Exchange` | 13/13 |
| 🟢 | `Initialize_Key_Exchange_Private` | 21/21 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 35/35 |
| 🟢 | `Set_Group` | 8/8 |
| 🟢 | `Set_Key_Exchange` | 38/38 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 10/10 |
| 🟢 | `To_Structure` | 10/10 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 12/12 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 24/24 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Key_Exchange_Len` | 9/10 |

</details>

<details>
<summary>🟢 <code>RFLX.New_Session_Ticket</code> — 5/5 subprograms · 5/5 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟡 <code>RFLX.New_Session_Ticket.Message</code> — 73/77 subprograms · 761/765 VCs (99%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Extensions` | 6/6 |
| 🟢 | `Field_First_Extensions_Len` | 5/5 |
| 🟢 | `Field_First_Internal` | 11/11 |
| 🟢 | `Field_First_Nonce_Len` | 2/2 |
| 🟢 | `Field_First_Ticket` | 6/6 |
| 🟢 | `Field_First_Ticket_Age_Add` | 2/2 |
| 🟢 | `Field_First_Ticket_Len` | 5/5 |
| 🟢 | `Field_First_Ticket_Lifetime` | 2/2 |
| 🟢 | `Field_First_Ticket_Nonce` | 2/2 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Field_Size_Internal` | 5/5 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Extensions` | 6/6 |
| 🟢 | `Get_Extensions` | 16/16 |
| 🟢 | `Get_Extensions_Len` | 1/1 |
| 🟢 | `Get_Nonce_Len` | 1/1 |
| 🟢 | `Get_Ticket` | 6/6 |
| 🟢 | `Get_Ticket` | 16/16 |
| 🟢 | `Get_Ticket_Age_Add` | 1/1 |
| 🟢 | `Get_Ticket_Len` | 1/1 |
| 🟢 | `Get_Ticket_Lifetime` | 1/1 |
| 🟢 | `Get_Ticket_Nonce` | 6/6 |
| 🟢 | `Get_Ticket_Nonce` | 16/16 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Extensions` | 19/19 |
| 🟢 | `Initialize_Extensions_Private` | 27/27 |
| 🟢 | `Initialize_Ticket` | 15/15 |
| 🟢 | `Initialize_Ticket_Nonce` | 13/13 |
| 🟢 | `Initialize_Ticket_Nonce_Private` | 23/23 |
| 🟢 | `Initialize_Ticket_Private` | 25/25 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 35/35 |
| 🟢 | `Set_Extensions` | 44/44 |
| 🟢 | `Set_Extensions_Empty` | 20/20 |
| 🟢 | `Set_Nonce_Len` | 12/12 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Set_Ticket` | 40/40 |
| 🟢 | `Set_Ticket_Nonce` | 38/38 |
| 🟢 | `Set_Ticket_Nonce_Empty` | 14/14 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 23/23 |
| 🟢 | `To_Structure` | 25/25 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 14/14 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 24/24 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Extensions_Len` | 15/16 |
| 🟡 | `Set_Ticket_Age_Add` | 9/10 |
| 🟡 | `Set_Ticket_Len` | 13/14 |
| 🟡 | `Set_Ticket_Lifetime` | 7/8 |

</details>

<details>
<summary>🟢 <code>RFLX.Ping.Packet</code> — 45/45 subprograms · 289/289 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Internal` | 4/4 |
| 🟢 | `Field_First_Opaque_Data` | 2/2 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Field_Size_Internal` | 2/2 |
| 🟢 | `Get_Opaque_Data` | 6/6 |
| 🟢 | `Get_Opaque_Data` | 16/16 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Opaque_Data` | 9/9 |
| 🟢 | `Initialize_Opaque_Data_Private` | 17/17 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set_Opaque_Data` | 34/34 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 5/5 |
| 🟢 | `To_Structure` | 8/8 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 11/11 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 17/17 |
| 🟢 | `Verify_Message` | 4/4 |

</details>

<details>
<summary>🟢 <code>RFLX.Pingreq</code> — 2/2 subprograms · 2/2 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟢 <code>RFLX.Pingreq.Packet</code> — 50/50 subprograms · 292/292 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Internal` | 6/6 |
| 🟢 | `Field_First_Packet_Type` | 2/2 |
| 🟢 | `Field_First_Remaining_Length` | 2/2 |
| 🟢 | `Field_First_Reserved` | 2/2 |
| 🟢 | `Field_Last` | 4/4 |
| 🟢 | `Field_Size` | 2/2 |
| 🟢 | `Field_Size_Internal` | 2/2 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Packet_Type` | 1/1 |
| 🟢 | `Get_Remaining_Length` | 1/1 |
| 🟢 | `Get_Reserved` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 34/34 |
| 🟢 | `Set_Packet_Type` | 9/9 |
| 🟢 | `Set_Remaining_Length` | 11/11 |
| 🟢 | `Set_Reserved` | 9/9 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 6/6 |
| 🟢 | `To_Structure` | 5/5 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 11/11 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 21/21 |
| 🟢 | `Verify_Message` | 4/4 |

</details>

<details>
<summary>🟢 <code>RFLX.Pingresp</code> — 2/2 subprograms · 2/2 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟢 <code>RFLX.Pingresp.Packet</code> — 50/50 subprograms · 292/292 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Internal` | 6/6 |
| 🟢 | `Field_First_Packet_Type` | 2/2 |
| 🟢 | `Field_First_Remaining_Length` | 2/2 |
| 🟢 | `Field_First_Reserved` | 2/2 |
| 🟢 | `Field_Last` | 4/4 |
| 🟢 | `Field_Size` | 2/2 |
| 🟢 | `Field_Size_Internal` | 2/2 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Packet_Type` | 1/1 |
| 🟢 | `Get_Remaining_Length` | 1/1 |
| 🟢 | `Get_Reserved` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 34/34 |
| 🟢 | `Set_Packet_Type` | 9/9 |
| 🟢 | `Set_Remaining_Length` | 11/11 |
| 🟢 | `Set_Reserved` | 9/9 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 6/6 |
| 🟢 | `To_Structure` | 5/5 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 11/11 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 21/21 |
| 🟢 | `Verify_Message` | 4/4 |

</details>

<details>
<summary>🟢 <code>RFLX.Pre_Shared_Key</code> — 6/6 subprograms · 6/6 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟡 <code>RFLX.Pre_Shared_Key.Client_Hello_Payload</code> — 58/60 subprograms · 514/516 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Binders` | 6/6 |
| 🟢 | `Field_First_Binders_Len` | 5/5 |
| 🟢 | `Field_First_Identities` | 2/2 |
| 🟢 | `Field_First_Identities_Len` | 2/2 |
| 🟢 | `Field_First_Internal` | 7/7 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Field_Size_Internal` | 4/4 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Binders` | 6/6 |
| 🟢 | `Get_Binders` | 16/16 |
| 🟢 | `Get_Binders_Len` | 1/1 |
| 🟢 | `Get_Identities` | 6/6 |
| 🟢 | `Get_Identities` | 16/16 |
| 🟢 | `Get_Identities_Len` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Binders` | 13/13 |
| 🟢 | `Initialize_Binders_Private` | 21/21 |
| 🟢 | `Initialize_Identities` | 9/9 |
| 🟢 | `Initialize_Identities_Private` | 19/19 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 35/35 |
| 🟢 | `Set_Binders` | 38/38 |
| 🟢 | `Set_Identities` | 34/34 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 15/15 |
| 🟢 | `To_Structure` | 16/16 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 13/13 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 24/24 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Binders_Len` | 9/10 |
| 🟡 | `Set_Identities_Len` | 7/8 |

</details>

<details>
<summary>🟢 <code>RFLX.Pre_Shared_Key.Psk_Binder_Entry</code> — 51/51 subprograms · 387/387 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Binder` | 2/2 |
| 🟢 | `Field_First_Binder_Len` | 2/2 |
| 🟢 | `Field_First_Internal` | 5/5 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Field_Size_Internal` | 3/3 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Binder` | 6/6 |
| 🟢 | `Get_Binder` | 16/16 |
| 🟢 | `Get_Binder_Len` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Binder` | 11/11 |
| 🟢 | `Initialize_Binder_Private` | 19/19 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 35/35 |
| 🟢 | `Set_Binder` | 36/36 |
| 🟢 | `Set_Binder_Len` | 8/8 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 9/9 |
| 🟢 | `To_Structure` | 9/9 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 12/12 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 24/24 |
| 🟢 | `Verify_Message` | 4/4 |

</details>

<details>
<summary>🟡 <code>RFLX.Pre_Shared_Key.Psk_Identity</code> — 52/54 subprograms · 402/404 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Identity` | 2/2 |
| 🟢 | `Field_First_Identity_Len` | 2/2 |
| 🟢 | `Field_First_Internal` | 6/6 |
| 🟢 | `Field_First_Obfuscated_Ticket_Age` | 5/5 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Field_Size_Internal` | 3/3 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Identity` | 6/6 |
| 🟢 | `Get_Identity` | 16/16 |
| 🟢 | `Get_Identity_Len` | 1/1 |
| 🟢 | `Get_Obfuscated_Ticket_Age` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Identity` | 9/9 |
| 🟢 | `Initialize_Identity_Private` | 19/19 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 35/35 |
| 🟢 | `Set_Identity` | 34/34 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 10/10 |
| 🟢 | `To_Structure` | 10/10 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 12/12 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 24/24 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Identity_Len` | 7/8 |
| 🟡 | `Set_Obfuscated_Ticket_Age` | 11/12 |

</details>

<details>
<summary>🟡 <code>RFLX.Pre_Shared_Key.Server_Hello_Payload</code> — 43/44 subprograms · 257/258 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Internal` | 4/4 |
| 🟢 | `Field_First_Selected_Identity` | 2/2 |
| 🟢 | `Field_Last` | 4/4 |
| 🟢 | `Field_Size` | 2/2 |
| 🟢 | `Field_Size_Internal` | 2/2 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Selected_Identity` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 34/34 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 4/4 |
| 🟢 | `To_Structure` | 3/3 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 11/11 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 18/18 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Selected_Identity` | 9/10 |

</details>

<details>
<summary>🟢 <code>RFLX.Puback</code> — 2/2 subprograms · 2/2 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟡 <code>RFLX.Puback.Packet</code> — 52/53 subprograms · 307/308 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Internal` | 7/7 |
| 🟢 | `Field_First_Packet_Identifier` | 2/2 |
| 🟢 | `Field_First_Packet_Type` | 2/2 |
| 🟢 | `Field_First_Remaining_Length` | 2/2 |
| 🟢 | `Field_First_Reserved` | 2/2 |
| 🟢 | `Field_Last` | 4/4 |
| 🟢 | `Field_Size` | 2/2 |
| 🟢 | `Field_Size_Internal` | 2/2 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Packet_Identifier` | 1/1 |
| 🟢 | `Get_Packet_Type` | 1/1 |
| 🟢 | `Get_Remaining_Length` | 1/1 |
| 🟢 | `Get_Reserved` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 34/34 |
| 🟢 | `Set_Packet_Type` | 9/9 |
| 🟢 | `Set_Remaining_Length` | 9/9 |
| 🟢 | `Set_Reserved` | 9/9 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 7/7 |
| 🟢 | `To_Structure` | 6/6 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 11/11 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 21/21 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Packet_Identifier` | 11/12 |

</details>

<details>
<summary>🟢 <code>RFLX.Pubcomp</code> — 2/2 subprograms · 2/2 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟡 <code>RFLX.Pubcomp.Packet</code> — 52/53 subprograms · 307/308 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Internal` | 7/7 |
| 🟢 | `Field_First_Packet_Identifier` | 2/2 |
| 🟢 | `Field_First_Packet_Type` | 2/2 |
| 🟢 | `Field_First_Remaining_Length` | 2/2 |
| 🟢 | `Field_First_Reserved` | 2/2 |
| 🟢 | `Field_Last` | 4/4 |
| 🟢 | `Field_Size` | 2/2 |
| 🟢 | `Field_Size_Internal` | 2/2 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Packet_Identifier` | 1/1 |
| 🟢 | `Get_Packet_Type` | 1/1 |
| 🟢 | `Get_Remaining_Length` | 1/1 |
| 🟢 | `Get_Reserved` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 34/34 |
| 🟢 | `Set_Packet_Type` | 9/9 |
| 🟢 | `Set_Remaining_Length` | 9/9 |
| 🟢 | `Set_Reserved` | 9/9 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 7/7 |
| 🟢 | `To_Structure` | 6/6 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 11/11 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 21/21 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Packet_Identifier` | 11/12 |

</details>

<details>
<summary>🟢 <code>RFLX.Publish</code> — 2/2 subprograms · 2/2 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟡 <code>RFLX.Publish.Packet</code> — 72/74 subprograms · 730/732 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 4/4 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_DUP` | 2/2 |
| 🟢 | `Field_First_Internal` | 12/12 |
| 🟢 | `Field_First_Packet_Identifier` | 5/5 |
| 🟢 | `Field_First_Packet_Type` | 2/2 |
| 🟢 | `Field_First_Payload` | 11/11 |
| 🟢 | `Field_First_QoS` | 2/2 |
| 🟢 | `Field_First_Remaining_Length` | 2/2 |
| 🟢 | `Field_First_Retain` | 2/2 |
| 🟢 | `Field_First_Topic_Name` | 2/2 |
| 🟢 | `Field_First_Topic_Name_Length` | 2/2 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Field_Size_Internal` | 12/12 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_DUP` | 1/1 |
| 🟢 | `Get_Packet_Identifier` | 1/1 |
| 🟢 | `Get_Packet_Type` | 1/1 |
| 🟢 | `Get_Payload` | 6/6 |
| 🟢 | `Get_Payload` | 16/16 |
| 🟢 | `Get_QoS` | 1/1 |
| 🟢 | `Get_Remaining_Length` | 1/1 |
| 🟢 | `Get_Retain` | 1/1 |
| 🟢 | `Get_Topic_Name` | 6/6 |
| 🟢 | `Get_Topic_Name` | 16/16 |
| 🟢 | `Get_Topic_Name_Length` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Payload` | 21/21 |
| 🟢 | `Initialize_Payload_Private` | 29/29 |
| 🟢 | `Initialize_Topic_Name` | 26/26 |
| 🟢 | `Initialize_Topic_Name_Private` | 36/36 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 35/35 |
| 🟢 | `Set_DUP` | 10/10 |
| 🟢 | `Set_Packet_Type` | 9/9 |
| 🟢 | `Set_Payload` | 46/46 |
| 🟢 | `Set_Payload_Empty` | 22/22 |
| 🟢 | `Set_QoS` | 12/12 |
| 🟢 | `Set_Remaining_Length` | 16/16 |
| 🟢 | `Set_Retain` | 14/14 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Set_Topic_Name` | 51/51 |
| 🟢 | `Set_Topic_Name_Empty` | 27/27 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 17/17 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 4/4 |
| 🟢 | `Valid_Predecessors_Invariant` | 3/3 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 24/24 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Packet_Identifier` | 19/20 |
| 🟡 | `Set_Topic_Name_Length` | 17/18 |

</details>

<details>
<summary>🟢 <code>RFLX.Pubrec</code> — 2/2 subprograms · 2/2 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟡 <code>RFLX.Pubrec.Packet</code> — 52/53 subprograms · 307/308 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Internal` | 7/7 |
| 🟢 | `Field_First_Packet_Identifier` | 2/2 |
| 🟢 | `Field_First_Packet_Type` | 2/2 |
| 🟢 | `Field_First_Remaining_Length` | 2/2 |
| 🟢 | `Field_First_Reserved` | 2/2 |
| 🟢 | `Field_Last` | 4/4 |
| 🟢 | `Field_Size` | 2/2 |
| 🟢 | `Field_Size_Internal` | 2/2 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Packet_Identifier` | 1/1 |
| 🟢 | `Get_Packet_Type` | 1/1 |
| 🟢 | `Get_Remaining_Length` | 1/1 |
| 🟢 | `Get_Reserved` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 34/34 |
| 🟢 | `Set_Packet_Type` | 9/9 |
| 🟢 | `Set_Remaining_Length` | 9/9 |
| 🟢 | `Set_Reserved` | 9/9 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 7/7 |
| 🟢 | `To_Structure` | 6/6 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 11/11 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 21/21 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Packet_Identifier` | 11/12 |

</details>

<details>
<summary>🟢 <code>RFLX.Pubrel</code> — 2/2 subprograms · 2/2 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟡 <code>RFLX.Pubrel.Packet</code> — 52/53 subprograms · 307/308 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Internal` | 7/7 |
| 🟢 | `Field_First_Packet_Identifier` | 2/2 |
| 🟢 | `Field_First_Packet_Type` | 2/2 |
| 🟢 | `Field_First_Remaining_Length` | 2/2 |
| 🟢 | `Field_First_Reserved` | 2/2 |
| 🟢 | `Field_Last` | 4/4 |
| 🟢 | `Field_Size` | 2/2 |
| 🟢 | `Field_Size_Internal` | 2/2 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Packet_Identifier` | 1/1 |
| 🟢 | `Get_Packet_Type` | 1/1 |
| 🟢 | `Get_Remaining_Length` | 1/1 |
| 🟢 | `Get_Reserved` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 34/34 |
| 🟢 | `Set_Packet_Type` | 9/9 |
| 🟢 | `Set_Remaining_Length` | 9/9 |
| 🟢 | `Set_Reserved` | 9/9 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 7/7 |
| 🟢 | `To_Structure` | 6/6 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 11/11 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 21/21 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Packet_Identifier` | 11/12 |

</details>

<details>
<summary>🟢 <code>RFLX.Record_Layer</code> — 2/2 subprograms · 2/2 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟡 <code>RFLX.Record_Layer.Plaintext</code> — 56/58 subprograms · 447/449 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Fragment` | 2/2 |
| 🟢 | `Field_First_Internal` | 7/7 |
| 🟢 | `Field_First_Legacy_Version` | 2/2 |
| 🟢 | `Field_First_Length` | 2/2 |
| 🟢 | `Field_First_Type_Field` | 2/2 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Field_Size_Internal` | 3/3 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Fragment` | 6/6 |
| 🟢 | `Get_Fragment` | 16/16 |
| 🟢 | `Get_Legacy_Version` | 1/1 |
| 🟢 | `Get_Length` | 1/1 |
| 🟢 | `Get_Type_Field` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Fragment` | 15/15 |
| 🟢 | `Initialize_Fragment_Private` | 23/23 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 35/35 |
| 🟢 | `Set_Fragment` | 40/40 |
| 🟢 | `Set_Fragment_Empty` | 16/16 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Set_Type_Field` | 8/8 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 11/11 |
| 🟢 | `To_Structure` | 11/11 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 12/12 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 24/24 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Legacy_Version` | 9/10 |
| 🟡 | `Set_Length` | 11/12 |

</details>

<details>
<summary>🟢 <code>RFLX.Rst_Stream</code> — 1/1 subprograms · 1/1 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟡 <code>RFLX.Rst_Stream.Packet</code> — 43/44 subprograms · 257/258 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Error_Code` | 2/2 |
| 🟢 | `Field_First_Internal` | 4/4 |
| 🟢 | `Field_Last` | 4/4 |
| 🟢 | `Field_Size` | 2/2 |
| 🟢 | `Field_Size_Internal` | 2/2 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Error_Code` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 34/34 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 4/4 |
| 🟢 | `To_Structure` | 3/3 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 11/11 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 18/18 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Error_Code` | 9/10 |

</details>

<details>
<summary>🟢 <code>RFLX.SH_Decode_Session.Decode.FSM</code> — 12/12 subprograms · 61/61 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Accessible_Buffer` | 1/1 |
| 🟢 | `Add_Buffer` | 11/11 |
| 🟢 | `Await_SH` | 5/5 |
| 🟢 | `Finalize` | 3/3 |
| 🟢 | `Initialize` | 6/6 |
| 🟢 | `Private_Context` | 3/3 |
| 🟢 | `Remove_Buffer` | 10/10 |
| 🟢 | `Reset_Messages_Before_Write` | 2/2 |
| 🟢 | `Run` | 5/5 |
| 🟢 | `Tick` | 3/3 |
| 🟢 | `Write` | 9/9 |
| 🟢 | `Write_Buffer_Size` | 3/3 |

</details>

<details>
<summary>🟢 <code>RFLX.SH_Decode_Session.Decode.FSM.Write</code> — 2/2 subprograms · 24/24 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Write` | 20/20 |
| 🟢 | `Write_Pre` | 4/4 |

</details>

<details>
<summary>🟢 <code>RFLX.SH_Decode_Session.Decode.FSM.Write.SERVER_HELLO_MESSAGE_WRITEGP5444</code> — 1/1 subprograms · 22/22 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Server_Hello_Message_Write` | 22/22 |

</details>

<details>
<summary>🟢 <code>RFLX.Server_Hello</code> — 5/5 subprograms · 5/5 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟡 <code>RFLX.Server_Hello.Message</code> — 73/76 subprograms · 674/677 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Compression_Method_Val` | 6/6 |
| 🟢 | `Field_First_Extensions` | 6/6 |
| 🟢 | `Field_First_Extensions_Len` | 6/6 |
| 🟢 | `Field_First_Internal` | 11/11 |
| 🟢 | `Field_First_Legacy_Version_Field` | 2/2 |
| 🟢 | `Field_First_Random` | 2/2 |
| 🟢 | `Field_First_Selected_Cipher_Suite` | 5/5 |
| 🟢 | `Field_First_Session_Id_Echo` | 2/2 |
| 🟢 | `Field_First_Session_Id_Len` | 2/2 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Field_Size_Internal` | 4/4 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Compression_Method_Val` | 1/1 |
| 🟢 | `Get_Extensions` | 6/6 |
| 🟢 | `Get_Extensions` | 16/16 |
| 🟢 | `Get_Extensions_Len` | 1/1 |
| 🟢 | `Get_Legacy_Version_Field` | 1/1 |
| 🟢 | `Get_Random` | 6/6 |
| 🟢 | `Get_Random` | 16/16 |
| 🟢 | `Get_Selected_Cipher_Suite` | 1/1 |
| 🟢 | `Get_Session_Id_Echo` | 6/6 |
| 🟢 | `Get_Session_Id_Echo` | 16/16 |
| 🟢 | `Get_Session_Id_Len` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Extensions` | 15/15 |
| 🟢 | `Initialize_Extensions_Private` | 23/23 |
| 🟢 | `Initialize_Random` | 7/7 |
| 🟢 | `Initialize_Random_Private` | 17/17 |
| 🟢 | `Initialize_Session_Id_Echo` | 9/9 |
| 🟢 | `Initialize_Session_Id_Echo_Private` | 19/19 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 35/35 |
| 🟢 | `Set_Compression_Method_Val` | 11/11 |
| 🟢 | `Set_Extensions` | 40/40 |
| 🟢 | `Set_Random` | 32/32 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Set_Session_Id_Echo` | 34/34 |
| 🟢 | `Set_Session_Id_Echo_Empty` | 10/10 |
| 🟢 | `Set_Session_Id_Len` | 8/8 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 20/20 |
| 🟢 | `To_Structure` | 25/25 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 13/13 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 24/24 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Extensions_Len` | 11/12 |
| 🟡 | `Set_Legacy_Version_Field` | 6/7 |
| 🟡 | `Set_Selected_Cipher_Suite` | 9/10 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Broker_Reading.FSM</code> — 18/18 subprograms · 113/113 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Accessible_Buffer` | 2/2 |
| 🟢 | `Add_Buffer` | 11/11 |
| 🟢 | `Awaiting_Connect` | 7/7 |
| 🟢 | `Finalize` | 3/3 |
| 🟢 | `Forwarding` | 4/4 |
| 🟢 | `Forwarding_Connect` | 4/4 |
| 🟢 | `Has_Data` | 1/1 |
| 🟢 | `Initialize` | 6/6 |
| 🟢 | `Private_Context` | 3/3 |
| 🟢 | `Read` | 10/10 |
| 🟢 | `Read_Buffer_Size` | 3/3 |
| 🟢 | `Reading` | 23/23 |
| 🟢 | `Remove_Buffer` | 10/10 |
| 🟢 | `Reset_Messages_Before_Write` | 3/3 |
| 🟢 | `Run` | 5/5 |
| 🟢 | `Tick` | 6/6 |
| 🟢 | `Write` | 9/9 |
| 🟢 | `Write_Buffer_Size` | 3/3 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Broker_Reading.FSM.Read</code> — 2/2 subprograms · 21/21 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Read` | 20/20 |
| 🟢 | `Read_Pre` | 1/1 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Broker_Reading.FSM.Read.CONTROL_PACKET_INCOMING_PACKET_READGP21879</code> — 1/1 subprograms · 6/6 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Control_Packet_Incoming_Packet_Read` | 6/6 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Broker_Reading.FSM.Write</code> — 2/2 subprograms · 24/24 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Write` | 20/20 |
| 🟢 | `Write_Pre` | 4/4 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Broker_Reading.FSM.Write.CONTROL_PACKET_INCOMING_PACKET_WRITEGP23887</code> — 1/1 subprograms · 22/22 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Control_Packet_Incoming_Packet_Write` | 22/22 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Connect_Handshake.FSM</code> — 19/19 subprograms · 117/117 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Accessible_Buffer` | 3/3 |
| 🟢 | `Add_Buffer` | 13/13 |
| 🟢 | `Awaiting_Connack` | 7/7 |
| 🟢 | `Buffer_Accessible` | 1/1 |
| 🟢 | `Finalize` | 5/5 |
| 🟢 | `Forwarding_Connack` | 4/4 |
| 🟢 | `Has_Data` | 2/2 |
| 🟢 | `Initialize` | 11/11 |
| 🟢 | `Loading` | 5/5 |
| 🟢 | `Private_Context` | 6/6 |
| 🟢 | `Read` | 11/11 |
| 🟢 | `Read_Buffer_Size` | 4/4 |
| 🟢 | `Remove_Buffer` | 12/12 |
| 🟢 | `Reset_Messages_Before_Write` | 3/3 |
| 🟢 | `Run` | 5/5 |
| 🟢 | `Sending` | 4/4 |
| 🟢 | `Tick` | 6/6 |
| 🟢 | `Write` | 10/10 |
| 🟢 | `Write_Buffer_Size` | 5/5 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Connect_Handshake.FSM.Read</code> — 2/2 subprograms · 21/21 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Read` | 20/20 |
| 🟢 | `Read_Pre` | 1/1 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Connect_Handshake.FSM.Read.CONNECT_PACKET_READGP10081</code> — 1/1 subprograms · 6/6 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Connect_Packet_Read` | 6/6 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Connect_Handshake.FSM.Read.CONTROL_PACKET_INCOMING_PACKET_READGP10170</code> — 1/1 subprograms · 6/6 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Control_Packet_Incoming_Packet_Read` | 6/6 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Connect_Handshake.FSM.Write</code> — 2/2 subprograms · 24/24 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Write` | 20/20 |
| 🟢 | `Write_Pre` | 4/4 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Connect_Handshake.FSM.Write.CONNECT_PACKET_WRITEGP12520</code> — 1/1 subprograms · 22/22 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Connect_Packet_Write` | 22/22 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Connect_Handshake.FSM.Write.CONTROL_PACKET_INCOMING_PACKET_WRITEGP12613</code> — 1/1 subprograms · 22/22 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Control_Packet_Incoming_Packet_Write` | 22/22 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Publish_Qos1.FSM</code> — 20/20 subprograms · 138/138 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Accessible_Buffer` | 3/3 |
| 🟢 | `Add_Buffer` | 13/13 |
| 🟢 | `Awaiting_Puback` | 23/23 |
| 🟢 | `Buffer_Accessible` | 1/1 |
| 🟢 | `Finalize` | 5/5 |
| 🟢 | `Forwarding_Inbound_Publish` | 4/4 |
| 🟢 | `Forwarding_Puback` | 4/4 |
| 🟢 | `Has_Data` | 2/2 |
| 🟢 | `Initialize` | 11/11 |
| 🟢 | `Loading` | 5/5 |
| 🟢 | `Private_Context` | 6/6 |
| 🟢 | `Read` | 11/11 |
| 🟢 | `Read_Buffer_Size` | 4/4 |
| 🟢 | `Remove_Buffer` | 12/12 |
| 🟢 | `Reset_Messages_Before_Write` | 3/3 |
| 🟢 | `Run` | 5/5 |
| 🟢 | `Sending` | 4/4 |
| 🟢 | `Tick` | 7/7 |
| 🟢 | `Write` | 10/10 |
| 🟢 | `Write_Buffer_Size` | 5/5 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Publish_Qos1.FSM.Read</code> — 2/2 subprograms · 21/21 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Read` | 20/20 |
| 🟢 | `Read_Pre` | 1/1 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Publish_Qos1.FSM.Read.CONTROL_PACKET_INCOMING_PACKET_READGP21092</code> — 1/1 subprograms · 6/6 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Control_Packet_Incoming_Packet_Read` | 6/6 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Publish_Qos1.FSM.Read.PUBLISH_PACKET_READGP21213</code> — 1/1 subprograms · 6/6 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Publish_Packet_Read` | 6/6 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Publish_Qos1.FSM.Write</code> — 2/2 subprograms · 24/24 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Write` | 20/20 |
| 🟢 | `Write_Pre` | 4/4 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Publish_Qos1.FSM.Write.CONTROL_PACKET_INCOMING_PACKET_WRITEGP23561</code> — 1/1 subprograms · 22/22 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Control_Packet_Incoming_Packet_Write` | 22/22 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Publish_Qos1.FSM.Write.PUBLISH_PACKET_WRITEGP23686</code> — 1/1 subprograms · 22/22 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Publish_Packet_Write` | 22/22 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Publish_Qos2.FSM</code> — 23/23 subprograms · 173/173 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Accessible_Buffer` | 3/3 |
| 🟢 | `Add_Buffer` | 13/13 |
| 🟢 | `Awaiting_Pubcomp` | 23/23 |
| 🟢 | `Awaiting_Pubrec` | 23/23 |
| 🟢 | `Buffer_Accessible` | 1/1 |
| 🟢 | `Finalize` | 5/5 |
| 🟢 | `Forwarding_Inbound_Publish` | 4/4 |
| 🟢 | `Forwarding_Inbound_Publish_2` | 4/4 |
| 🟢 | `Forwarding_Pubcomp` | 4/4 |
| 🟢 | `Forwarding_Pubrec` | 4/4 |
| 🟢 | `Has_Data` | 2/2 |
| 🟢 | `Initialize` | 11/11 |
| 🟢 | `Loading` | 5/5 |
| 🟢 | `Private_Context` | 6/6 |
| 🟢 | `Read` | 11/11 |
| 🟢 | `Read_Buffer_Size` | 4/4 |
| 🟢 | `Remove_Buffer` | 12/12 |
| 🟢 | `Reset_Messages_Before_Write` | 4/4 |
| 🟢 | `Run` | 5/5 |
| 🟢 | `Sending` | 4/4 |
| 🟢 | `Tick` | 10/10 |
| 🟢 | `Write` | 10/10 |
| 🟢 | `Write_Buffer_Size` | 5/5 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Publish_Qos2.FSM.Read</code> — 2/2 subprograms · 21/21 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Read` | 20/20 |
| 🟢 | `Read_Pre` | 1/1 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Publish_Qos2.FSM.Read.CONTROL_PACKET_INCOMING_PACKET_READGP35447</code> — 1/1 subprograms · 6/6 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Control_Packet_Incoming_Packet_Read` | 6/6 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Publish_Qos2.FSM.Read.PUBLISH_PACKET_READGP35568</code> — 1/1 subprograms · 6/6 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Publish_Packet_Read` | 6/6 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Publish_Qos2.FSM.Write</code> — 2/2 subprograms · 24/24 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Write` | 20/20 |
| 🟢 | `Write_Pre` | 4/4 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Publish_Qos2.FSM.Write.CONTROL_PACKET_INCOMING_PACKET_WRITEGP37972</code> — 1/1 subprograms · 22/22 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Control_Packet_Incoming_Packet_Write` | 22/22 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Publish_Qos2.FSM.Write.PUBLISH_PACKET_WRITEGP38097</code> — 1/1 subprograms · 22/22 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Publish_Packet_Write` | 22/22 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Receive.FSM</code> — 16/16 subprograms · 98/98 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Accessible_Buffer` | 2/2 |
| 🟢 | `Add_Buffer` | 11/11 |
| 🟢 | `Finalize` | 3/3 |
| 🟢 | `Forwarding_Publish` | 4/4 |
| 🟢 | `Has_Data` | 1/1 |
| 🟢 | `Initialize` | 6/6 |
| 🟢 | `Private_Context` | 3/3 |
| 🟢 | `Read` | 10/10 |
| 🟢 | `Read_Buffer_Size` | 3/3 |
| 🟢 | `Reading` | 22/22 |
| 🟢 | `Remove_Buffer` | 10/10 |
| 🟢 | `Reset_Messages_Before_Write` | 2/2 |
| 🟢 | `Run` | 5/5 |
| 🟢 | `Tick` | 4/4 |
| 🟢 | `Write` | 9/9 |
| 🟢 | `Write_Buffer_Size` | 3/3 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Receive.FSM.Read</code> — 2/2 subprograms · 21/21 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Read` | 20/20 |
| 🟢 | `Read_Pre` | 1/1 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Receive.FSM.Read.CONTROL_PACKET_INCOMING_PACKET_READGP17421</code> — 1/1 subprograms · 6/6 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Control_Packet_Incoming_Packet_Read` | 6/6 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Receive.FSM.Write</code> — 2/2 subprograms · 24/24 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Write` | 20/20 |
| 🟢 | `Write_Pre` | 4/4 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Receive.FSM.Write.CONTROL_PACKET_INCOMING_PACKET_WRITEGP19414</code> — 1/1 subprograms · 22/22 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Control_Packet_Incoming_Packet_Write` | 22/22 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Receive_Qos2.FSM</code> — 19/19 subprograms · 132/132 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Accessible_Buffer` | 3/3 |
| 🟢 | `Add_Buffer` | 13/13 |
| 🟢 | `Awaiting_Pubrel` | 22/22 |
| 🟢 | `Buffer_Accessible` | 1/1 |
| 🟢 | `Finalize` | 5/5 |
| 🟢 | `Forwarding_Pubrel` | 4/4 |
| 🟢 | `Has_Data` | 2/2 |
| 🟢 | `Initialize` | 11/11 |
| 🟢 | `Loading_Pubrec` | 5/5 |
| 🟢 | `Private_Context` | 6/6 |
| 🟢 | `Read` | 11/11 |
| 🟢 | `Read_Buffer_Size` | 4/4 |
| 🟢 | `Remove_Buffer` | 12/12 |
| 🟢 | `Reset_Messages_Before_Write` | 3/3 |
| 🟢 | `Run` | 5/5 |
| 🟢 | `Sending_Pubrec` | 4/4 |
| 🟢 | `Tick` | 6/6 |
| 🟢 | `Write` | 10/10 |
| 🟢 | `Write_Buffer_Size` | 5/5 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Receive_Qos2.FSM.Read</code> — 2/2 subprograms · 21/21 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Read` | 20/20 |
| 🟢 | `Read_Pre` | 1/1 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Receive_Qos2.FSM.Read.CONTROL_PACKET_INCOMING_PACKET_READGP20202</code> — 1/1 subprograms · 6/6 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Control_Packet_Incoming_Packet_Read` | 6/6 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Receive_Qos2.FSM.Read.PUBREC_PACKET_READGP20323</code> — 1/1 subprograms · 6/6 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Pubrec_Packet_Read` | 6/6 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Receive_Qos2.FSM.Write</code> — 2/2 subprograms · 24/24 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Write` | 20/20 |
| 🟢 | `Write_Pre` | 4/4 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Receive_Qos2.FSM.Write.CONTROL_PACKET_INCOMING_PACKET_WRITEGP22642</code> — 1/1 subprograms · 22/22 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Control_Packet_Incoming_Packet_Write` | 22/22 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Receive_Qos2.FSM.Write.PUBREC_PACKET_WRITEGP22767</code> — 1/1 subprograms · 22/22 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Pubrec_Packet_Write` | 22/22 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Subscribing.FSM</code> — 20/20 subprograms · 138/138 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Accessible_Buffer` | 3/3 |
| 🟢 | `Add_Buffer` | 13/13 |
| 🟢 | `Awaiting_Suback` | 23/23 |
| 🟢 | `Buffer_Accessible` | 1/1 |
| 🟢 | `Finalize` | 5/5 |
| 🟢 | `Forwarding_Inbound_Publish` | 4/4 |
| 🟢 | `Forwarding_Suback` | 4/4 |
| 🟢 | `Has_Data` | 2/2 |
| 🟢 | `Initialize` | 11/11 |
| 🟢 | `Loading` | 5/5 |
| 🟢 | `Private_Context` | 6/6 |
| 🟢 | `Read` | 11/11 |
| 🟢 | `Read_Buffer_Size` | 4/4 |
| 🟢 | `Remove_Buffer` | 12/12 |
| 🟢 | `Reset_Messages_Before_Write` | 3/3 |
| 🟢 | `Run` | 5/5 |
| 🟢 | `Sending` | 4/4 |
| 🟢 | `Tick` | 7/7 |
| 🟢 | `Write` | 10/10 |
| 🟢 | `Write_Buffer_Size` | 5/5 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Subscribing.FSM.Read</code> — 2/2 subprograms · 21/21 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Read` | 20/20 |
| 🟢 | `Read_Pre` | 1/1 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Subscribing.FSM.Read.CONTROL_PACKET_INCOMING_PACKET_READGP21107</code> — 1/1 subprograms · 6/6 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Control_Packet_Incoming_Packet_Read` | 6/6 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Subscribing.FSM.Read.SUBSCRIBE_PACKET_READGP21228</code> — 1/1 subprograms · 6/6 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Subscribe_Packet_Read` | 6/6 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Subscribing.FSM.Write</code> — 2/2 subprograms · 24/24 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Write` | 20/20 |
| 🟢 | `Write_Pre` | 4/4 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Subscribing.FSM.Write.CONTROL_PACKET_INCOMING_PACKET_WRITEGP23582</code> — 1/1 subprograms · 22/22 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Control_Packet_Incoming_Packet_Write` | 22/22 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Subscribing.FSM.Write.SUBSCRIBE_PACKET_WRITEGP23707</code> — 1/1 subprograms · 22/22 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Subscribe_Packet_Write` | 22/22 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Unsubscribing.FSM</code> — 20/20 subprograms · 138/138 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Accessible_Buffer` | 3/3 |
| 🟢 | `Add_Buffer` | 13/13 |
| 🟢 | `Awaiting_Unsuback` | 23/23 |
| 🟢 | `Buffer_Accessible` | 1/1 |
| 🟢 | `Finalize` | 5/5 |
| 🟢 | `Forwarding_Inbound_Publish` | 4/4 |
| 🟢 | `Forwarding_Unsuback` | 4/4 |
| 🟢 | `Has_Data` | 2/2 |
| 🟢 | `Initialize` | 11/11 |
| 🟢 | `Loading` | 5/5 |
| 🟢 | `Private_Context` | 6/6 |
| 🟢 | `Read` | 11/11 |
| 🟢 | `Read_Buffer_Size` | 4/4 |
| 🟢 | `Remove_Buffer` | 12/12 |
| 🟢 | `Reset_Messages_Before_Write` | 3/3 |
| 🟢 | `Run` | 5/5 |
| 🟢 | `Sending` | 4/4 |
| 🟢 | `Tick` | 7/7 |
| 🟢 | `Write` | 10/10 |
| 🟢 | `Write_Buffer_Size` | 5/5 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Unsubscribing.FSM.Read</code> — 2/2 subprograms · 21/21 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Read` | 20/20 |
| 🟢 | `Read_Pre` | 1/1 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Unsubscribing.FSM.Read.CONTROL_PACKET_INCOMING_PACKET_READGP21203</code> — 1/1 subprograms · 6/6 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Control_Packet_Incoming_Packet_Read` | 6/6 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Unsubscribing.FSM.Read.UNSUBSCRIBE_PACKET_READGP21324</code> — 1/1 subprograms · 6/6 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Unsubscribe_Packet_Read` | 6/6 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Unsubscribing.FSM.Write</code> — 2/2 subprograms · 24/24 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Write` | 20/20 |
| 🟢 | `Write_Pre` | 4/4 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Unsubscribing.FSM.Write.CONTROL_PACKET_INCOMING_PACKET_WRITEGP23686</code> — 1/1 subprograms · 22/22 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Control_Packet_Incoming_Packet_Write` | 22/22 |

</details>

<details>
<summary>🟢 <code>RFLX.Session.Unsubscribing.FSM.Write.UNSUBSCRIBE_PACKET_WRITEGP23811</code> — 1/1 subprograms · 22/22 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Unsubscribe_Packet_Write` | 22/22 |

</details>

<details>
<summary>🟢 <code>RFLX.Settings</code> — 1/1 subprograms · 1/1 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟡 <code>RFLX.Settings.Packet</code> — 41/45 subprograms · 322/326 VCs (99%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Complete_Parameters` | 1/1 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Internal` | 4/4 |
| 🟢 | `Field_First_Parameters` | 2/2 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Parameters` | 9/9 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 35/35 |
| 🟢 | `Set_Parameters_Empty` | 10/10 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Switch_To_Parameters` | 26/26 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `Update_Parameters` | 17/17 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 12/12 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 17/17 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Data` | 5/6 |
| 🟡 | `Field_Size_Internal` | 2/3 |
| 🟡 | `Initialize_Parameters_Private` | 16/17 |
| 🟡 | `Set_Parameters` | 15/16 |

</details>

<details>
<summary>🟡 <code>RFLX.Settings.Parameter</code> — 45/48 subprograms · 283/286 VCs (99%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Identifier` | 2/2 |
| 🟢 | `Field_First_Internal` | 5/5 |
| 🟢 | `Field_First_Value` | 2/2 |
| 🟢 | `Field_Last` | 4/4 |
| 🟢 | `Field_Size` | 2/2 |
| 🟢 | `Field_Size_Internal` | 2/2 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Identifier` | 1/1 |
| 🟢 | `Get_Value` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 34/34 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 5/5 |
| 🟢 | `To_Structure` | 5/5 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 11/11 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 21/21 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Identifier` | 7/8 |
| 🟡 | `Set_Identifier` | 7/8 |
| 🟡 | `Set_Value` | 11/12 |

</details>

<details>
<summary>🟢 <code>RFLX.Settings.Parameter_List</code> — 13/13 subprograms · 96/96 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Append_Element` | 11/11 |
| 🟢 | `Available_Space` | 1/1 |
| 🟢 | `Context` | 2/2 |
| 🟢 | `Contextpredicate` | 5/5 |
| 🟢 | `Copy` | 9/9 |
| 🟢 | `Data` | 9/9 |
| 🟢 | `Initialize` | 11/11 |
| 🟢 | `Initialize` | 17/17 |
| 🟢 | `Reset` | 3/3 |
| 🟢 | `Size` | 1/1 |
| 🟢 | `Switch` | 7/7 |
| 🟢 | `Take_Buffer` | 6/6 |
| 🟢 | `Update` | 14/14 |

</details>

<details>
<summary>🟢 <code>RFLX.Stream.Bidi_Stream.FSM</code> — 25/25 subprograms · 201/201 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Accessible_Buffer` | 3/3 |
| 🟢 | `Add_Buffer` | 13/13 |
| 🟢 | `Buffer_Accessible` | 1/1 |
| 🟢 | `Closing_Local` | 28/28 |
| 🟢 | `Finalize` | 5/5 |
| 🟢 | `Forwarding_Connection_Frame` | 4/4 |
| 🟢 | `Forwarding_Inbound` | 4/4 |
| 🟢 | `Forwarding_Inbound_End` | 4/4 |
| 🟢 | `Forwarding_Reset` | 4/4 |
| 🟢 | `Has_Data` | 2/2 |
| 🟢 | `Initialize` | 11/11 |
| 🟢 | `Loading_Headers` | 5/5 |
| 🟢 | `Private_Context` | 6/6 |
| 🟢 | `Read` | 11/11 |
| 🟢 | `Read_Buffer_Size` | 4/4 |
| 🟢 | `Remove_Buffer` | 12/12 |
| 🟢 | `Reset_Messages_Before_Write` | 5/5 |
| 🟢 | `Run` | 5/5 |
| 🟢 | `Sending_Data` | 10/10 |
| 🟢 | `Sending_Headers` | 4/4 |
| 🟢 | `Tick` | 12/12 |
| 🟢 | `Try_Recv` | 28/28 |
| 🟢 | `Try_Send` | 5/5 |
| 🟢 | `Write` | 10/10 |
| 🟢 | `Write_Buffer_Size` | 5/5 |

</details>

<details>
<summary>🟢 <code>RFLX.Stream.Bidi_Stream.FSM.Read</code> — 2/2 subprograms · 21/21 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Read` | 20/20 |
| 🟢 | `Read_Pre` | 1/1 |

</details>

<details>
<summary>🟢 <code>RFLX.Stream.Bidi_Stream.FSM.Read.FRAME_PACKET_READGP38049</code> — 1/1 subprograms · 6/6 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Frame_Packet_Read` | 6/6 |

</details>

<details>
<summary>🟢 <code>RFLX.Stream.Bidi_Stream.FSM.Write</code> — 2/2 subprograms · 24/24 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Write` | 20/20 |
| 🟢 | `Write_Pre` | 4/4 |

</details>

<details>
<summary>🟢 <code>RFLX.Stream.Bidi_Stream.FSM.Write.FRAME_PACKET_WRITEGP40448</code> — 1/1 subprograms · 22/22 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Frame_Packet_Write` | 22/22 |

</details>

<details>
<summary>🟢 <code>RFLX.Stream.Client_Stream.FSM</code> — 23/23 subprograms · 166/166 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Accessible_Buffer` | 3/3 |
| 🟢 | `Add_Buffer` | 13/13 |
| 🟢 | `Awaiting_Reply` | 28/28 |
| 🟢 | `Buffer_Accessible` | 1/1 |
| 🟢 | `Finalize` | 5/5 |
| 🟢 | `Forwarding_Connection_Frame` | 4/4 |
| 🟢 | `Forwarding_Inbound` | 4/4 |
| 🟢 | `Forwarding_Reset` | 4/4 |
| 🟢 | `Has_Data` | 2/2 |
| 🟢 | `Initialize` | 11/11 |
| 🟢 | `Loading_Data` | 5/5 |
| 🟢 | `Loading_Headers` | 5/5 |
| 🟢 | `Private_Context` | 6/6 |
| 🟢 | `Read` | 11/11 |
| 🟢 | `Read_Buffer_Size` | 4/4 |
| 🟢 | `Remove_Buffer` | 12/12 |
| 🟢 | `Reset_Messages_Before_Write` | 4/4 |
| 🟢 | `Run` | 5/5 |
| 🟢 | `Sending_Data` | 10/10 |
| 🟢 | `Sending_Headers` | 4/4 |
| 🟢 | `Tick` | 10/10 |
| 🟢 | `Write` | 10/10 |
| 🟢 | `Write_Buffer_Size` | 5/5 |

</details>

<details>
<summary>🟢 <code>RFLX.Stream.Client_Stream.FSM.Read</code> — 2/2 subprograms · 21/21 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Read` | 20/20 |
| 🟢 | `Read_Pre` | 1/1 |

</details>

<details>
<summary>🟢 <code>RFLX.Stream.Client_Stream.FSM.Read.FRAME_PACKET_READGP26432</code> — 1/1 subprograms · 6/6 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Frame_Packet_Read` | 6/6 |

</details>

<details>
<summary>🟢 <code>RFLX.Stream.Client_Stream.FSM.Write</code> — 2/2 subprograms · 24/24 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Write` | 20/20 |
| 🟢 | `Write_Pre` | 4/4 |

</details>

<details>
<summary>🟢 <code>RFLX.Stream.Client_Stream.FSM.Write.FRAME_PACKET_WRITEGP28804</code> — 1/1 subprograms · 22/22 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Frame_Packet_Write` | 22/22 |

</details>

<details>
<summary>🟢 <code>RFLX.Stream.Half_Open.FSM</code> — 21/21 subprograms · 148/148 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Accessible_Buffer` | 3/3 |
| 🟢 | `Add_Buffer` | 13/13 |
| 🟢 | `Awaiting_Reply` | 28/28 |
| 🟢 | `Buffer_Accessible` | 1/1 |
| 🟢 | `Finalize` | 5/5 |
| 🟢 | `Forwarding_Connection_Frame` | 4/4 |
| 🟢 | `Forwarding_Inbound` | 4/4 |
| 🟢 | `Forwarding_Reset` | 4/4 |
| 🟢 | `Has_Data` | 2/2 |
| 🟢 | `Initialize` | 11/11 |
| 🟢 | `Loading` | 5/5 |
| 🟢 | `Private_Context` | 6/6 |
| 🟢 | `Read` | 11/11 |
| 🟢 | `Read_Buffer_Size` | 4/4 |
| 🟢 | `Remove_Buffer` | 12/12 |
| 🟢 | `Reset_Messages_Before_Write` | 3/3 |
| 🟢 | `Run` | 5/5 |
| 🟢 | `Sending_Headers` | 4/4 |
| 🟢 | `Tick` | 8/8 |
| 🟢 | `Write` | 10/10 |
| 🟢 | `Write_Buffer_Size` | 5/5 |

</details>

<details>
<summary>🟢 <code>RFLX.Stream.Half_Open.FSM.Read</code> — 2/2 subprograms · 21/21 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Read` | 20/20 |
| 🟢 | `Read_Pre` | 1/1 |

</details>

<details>
<summary>🟢 <code>RFLX.Stream.Half_Open.FSM.Read.FRAME_PACKET_READGP20129</code> — 1/1 subprograms · 6/6 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Frame_Packet_Read` | 6/6 |

</details>

<details>
<summary>🟢 <code>RFLX.Stream.Half_Open.FSM.Write</code> — 2/2 subprograms · 24/24 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Write` | 20/20 |
| 🟢 | `Write_Pre` | 4/4 |

</details>

<details>
<summary>🟢 <code>RFLX.Stream.Half_Open.FSM.Write.FRAME_PACKET_WRITEGP22484</code> — 1/1 subprograms · 22/22 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Frame_Packet_Write` | 22/22 |

</details>

<details>
<summary>🟢 <code>RFLX.Stream.Open.FSM</code> — 24/24 subprograms · 190/190 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Accessible_Buffer` | 3/3 |
| 🟢 | `Add_Buffer` | 13/13 |
| 🟢 | `Awaiting_Body` | 25/25 |
| 🟢 | `Awaiting_Headers` | 21/21 |
| 🟢 | `Buffer_Accessible` | 1/1 |
| 🟢 | `Finalize` | 5/5 |
| 🟢 | `Forwarding_Body` | 10/10 |
| 🟢 | `Forwarding_Connection_Frame` | 4/4 |
| 🟢 | `Forwarding_Connection_Frame_Body` | 4/4 |
| 🟢 | `Forwarding_Headers` | 4/4 |
| 🟢 | `Forwarding_Reset` | 4/4 |
| 🟢 | `Has_Data` | 2/2 |
| 🟢 | `Initialize` | 11/11 |
| 🟢 | `Loading_Response` | 5/5 |
| 🟢 | `Private_Context` | 6/6 |
| 🟢 | `Read` | 11/11 |
| 🟢 | `Read_Buffer_Size` | 4/4 |
| 🟢 | `Remove_Buffer` | 12/12 |
| 🟢 | `Reset_Messages_Before_Write` | 4/4 |
| 🟢 | `Run` | 5/5 |
| 🟢 | `Sending_Response` | 10/10 |
| 🟢 | `Tick` | 11/11 |
| 🟢 | `Write` | 10/10 |
| 🟢 | `Write_Buffer_Size` | 5/5 |

</details>

<details>
<summary>🟢 <code>RFLX.Stream.Open.FSM.Read</code> — 2/2 subprograms · 21/21 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Read` | 20/20 |
| 🟢 | `Read_Pre` | 1/1 |

</details>

<details>
<summary>🟢 <code>RFLX.Stream.Open.FSM.Read.FRAME_PACKET_READGP37402</code> — 1/1 subprograms · 6/6 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Frame_Packet_Read` | 6/6 |

</details>

<details>
<summary>🟢 <code>RFLX.Stream.Open.FSM.Write</code> — 2/2 subprograms · 24/24 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Write` | 20/20 |
| 🟢 | `Write_Pre` | 4/4 |

</details>

<details>
<summary>🟢 <code>RFLX.Stream.Open.FSM.Write.FRAME_PACKET_WRITEGP39815</code> — 1/1 subprograms · 22/22 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Frame_Packet_Write` | 22/22 |

</details>

<details>
<summary>🟢 <code>RFLX.Suback</code> — 2/2 subprograms · 2/2 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟡 <code>RFLX.Suback.Packet</code> — 57/58 subprograms · 428/429 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Complete_Return_Codes` | 1/1 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Internal` | 8/8 |
| 🟢 | `Field_First_Packet_Identifier` | 2/2 |
| 🟢 | `Field_First_Packet_Type` | 2/2 |
| 🟢 | `Field_First_Remaining_Length` | 2/2 |
| 🟢 | `Field_First_Reserved` | 2/2 |
| 🟢 | `Field_First_Return_Codes` | 2/2 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Field_Size_Internal` | 3/3 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Packet_Identifier` | 1/1 |
| 🟢 | `Get_Packet_Type` | 1/1 |
| 🟢 | `Get_Remaining_Length` | 1/1 |
| 🟢 | `Get_Reserved` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Return_Codes` | 15/15 |
| 🟢 | `Initialize_Return_Codes_Private` | 23/23 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 35/35 |
| 🟢 | `Set_Packet_Type` | 9/9 |
| 🟢 | `Set_Remaining_Length` | 10/10 |
| 🟢 | `Set_Reserved` | 9/9 |
| 🟢 | `Set_Return_Codes` | 22/22 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Switch_To_Return_Codes` | 26/26 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `Update_Return_Codes` | 17/17 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 12/12 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 24/24 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Packet_Identifier` | 12/13 |

</details>

<details>
<summary>🟢 <code>RFLX.Suback.Return_Code_List</code> — 14/14 subprograms · 94/94 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Append_Element` | 15/15 |
| 🟢 | `Available_Space` | 1/1 |
| 🟢 | `Context` | 2/2 |
| 🟢 | `Contextpredicate` | 3/3 |
| 🟢 | `Copy` | 9/9 |
| 🟢 | `Data` | 9/9 |
| 🟢 | `Get_Element` | 1/1 |
| 🟢 | `Head` | 1/1 |
| 🟢 | `Initialize` | 11/11 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Next` | 16/16 |
| 🟢 | `Reset` | 3/3 |
| 🟢 | `Size` | 1/1 |
| 🟢 | `Take_Buffer` | 6/6 |

</details>

<details>
<summary>🟢 <code>RFLX.Subscribe</code> — 3/3 subprograms · 3/3 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟡 <code>RFLX.Subscribe.Packet</code> — 57/58 subprograms · 428/429 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Complete_Subscriptions` | 1/1 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Internal` | 8/8 |
| 🟢 | `Field_First_Packet_Identifier` | 2/2 |
| 🟢 | `Field_First_Packet_Type` | 2/2 |
| 🟢 | `Field_First_Remaining_Length` | 2/2 |
| 🟢 | `Field_First_Reserved` | 2/2 |
| 🟢 | `Field_First_Subscriptions` | 2/2 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Field_Size_Internal` | 3/3 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Packet_Identifier` | 1/1 |
| 🟢 | `Get_Packet_Type` | 1/1 |
| 🟢 | `Get_Remaining_Length` | 1/1 |
| 🟢 | `Get_Reserved` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Subscriptions` | 15/15 |
| 🟢 | `Initialize_Subscriptions_Private` | 23/23 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 35/35 |
| 🟢 | `Set_Packet_Type` | 9/9 |
| 🟢 | `Set_Remaining_Length` | 10/10 |
| 🟢 | `Set_Reserved` | 9/9 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Set_Subscriptions` | 22/22 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Switch_To_Subscriptions` | 26/26 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `Update_Subscriptions` | 17/17 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 12/12 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 24/24 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Packet_Identifier` | 12/13 |

</details>

<details>
<summary>🟡 <code>RFLX.Subscribe.Subscription</code> — 57/58 subprograms · 432/433 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Internal` | 7/7 |
| 🟢 | `Field_First_Requested_QoS` | 6/6 |
| 🟢 | `Field_First_Reserved_Sub_QoS` | 5/5 |
| 🟢 | `Field_First_Topic_Filter` | 2/2 |
| 🟢 | `Field_First_Topic_Filter_Length` | 2/2 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Field_Size_Internal` | 3/3 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Requested_QoS` | 1/1 |
| 🟢 | `Get_Reserved_Sub_QoS` | 1/1 |
| 🟢 | `Get_Topic_Filter` | 6/6 |
| 🟢 | `Get_Topic_Filter` | 16/16 |
| 🟢 | `Get_Topic_Filter_Length` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Topic_Filter` | 9/9 |
| 🟢 | `Initialize_Topic_Filter_Private` | 19/19 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 35/35 |
| 🟢 | `Set_Requested_QoS` | 12/12 |
| 🟢 | `Set_Reserved_Sub_QoS` | 9/9 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Set_Topic_Filter` | 34/34 |
| 🟢 | `Set_Topic_Filter_Empty` | 10/10 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 11/11 |
| 🟢 | `To_Structure` | 11/11 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 12/12 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 24/24 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Topic_Filter_Length` | 7/8 |

</details>

<details>
<summary>🟢 <code>RFLX.Subscribe.Subscription_List</code> — 13/13 subprograms · 96/96 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Append_Element` | 11/11 |
| 🟢 | `Available_Space` | 1/1 |
| 🟢 | `Context` | 2/2 |
| 🟢 | `Contextpredicate` | 5/5 |
| 🟢 | `Copy` | 9/9 |
| 🟢 | `Data` | 9/9 |
| 🟢 | `Initialize` | 11/11 |
| 🟢 | `Initialize` | 17/17 |
| 🟢 | `Reset` | 3/3 |
| 🟢 | `Size` | 1/1 |
| 🟢 | `Switch` | 7/7 |
| 🟢 | `Take_Buffer` | 6/6 |
| 🟢 | `Update` | 14/14 |

</details>

<details>
<summary>🟢 <code>RFLX.TLS_Extensions</code> — 2/2 subprograms · 2/2 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟡 <code>RFLX.TLS_Extensions.Extension</code> — 53/55 subprograms · 421/423 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Data` | 2/2 |
| 🟢 | `Field_First_Ext_Type` | 2/2 |
| 🟢 | `Field_First_Internal` | 6/6 |
| 🟢 | `Field_First_Length` | 2/2 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Field_Size_Internal` | 3/3 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Data` | 6/6 |
| 🟢 | `Get_Data` | 16/16 |
| 🟢 | `Get_Ext_Type` | 1/1 |
| 🟢 | `Get_Length` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Data` | 13/13 |
| 🟢 | `Initialize_Data_Private` | 21/21 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 35/35 |
| 🟢 | `Set_Data` | 38/38 |
| 🟢 | `Set_Data_Empty` | 14/14 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 10/10 |
| 🟢 | `To_Structure` | 10/10 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 12/12 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 24/24 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Ext_Type` | 7/8 |
| 🟡 | `Set_Length` | 9/10 |

</details>

<details>
<summary>🟢 <code>RFLX.TLS_Extensions.Extension_List</code> — 13/13 subprograms · 96/96 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Append_Element` | 11/11 |
| 🟢 | `Available_Space` | 1/1 |
| 🟢 | `Context` | 2/2 |
| 🟢 | `Contextpredicate` | 5/5 |
| 🟢 | `Copy` | 9/9 |
| 🟢 | `Data` | 9/9 |
| 🟢 | `Initialize` | 11/11 |
| 🟢 | `Initialize` | 17/17 |
| 🟢 | `Reset` | 3/3 |
| 🟢 | `Size` | 1/1 |
| 🟢 | `Switch` | 7/7 |
| 🟢 | `Take_Buffer` | 6/6 |
| 🟢 | `Update` | 14/14 |

</details>

<details>
<summary>🟢 <code>RFLX.TLS_Record_Reader.Reader.FSM</code> — 13/13 subprograms · 65/65 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Await_Record` | 5/5 |
| 🟢 | `Finalize` | 9/9 |
| 🟢 | `Forward` | 3/3 |
| 🟢 | `Has_Data` | 1/1 |
| 🟢 | `Initialize` | 7/7 |
| 🟢 | `Private_Context` | 4/4 |
| 🟢 | `Read` | 10/10 |
| 🟢 | `Read_Buffer_Size` | 3/3 |
| 🟢 | `Reset_Messages_Before_Write` | 2/2 |
| 🟢 | `Run` | 5/5 |
| 🟢 | `Tick` | 4/4 |
| 🟢 | `Write` | 9/9 |
| 🟢 | `Write_Buffer_Size` | 3/3 |

</details>

<details>
<summary>🟢 <code>RFLX.TLS_Record_Reader.Reader.FSM.Read</code> — 2/2 subprograms · 21/21 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Read` | 20/20 |
| 🟢 | `Read_Pre` | 1/1 |

</details>

<details>
<summary>🟢 <code>RFLX.TLS_Record_Reader.Reader.FSM.Read.RECORD_LAYER_PLAINTEXT_READGP5647</code> — 1/1 subprograms · 6/6 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Record_Layer_Plaintext_Read` | 6/6 |

</details>

<details>
<summary>🟢 <code>RFLX.TLS_Record_Reader.Reader.FSM.Write</code> — 2/2 subprograms · 24/24 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Write` | 20/20 |
| 🟢 | `Write_Pre` | 4/4 |

</details>

<details>
<summary>🟢 <code>RFLX.TLS_Record_Reader.Reader.FSM.Write.RECORD_LAYER_PLAINTEXT_WRITEGP7607</code> — 1/1 subprograms · 22/22 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Record_Layer_Plaintext_Write` | 22/22 |

</details>

<details>
<summary>🟢 <code>RFLX.TLS_Record_Reader.Reader.FSM_Allocator</code> — 1/3 subprograms · 2/2 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `SLOT_PTR_TYPE_4096PREDICATE` | 2/2 |
| ⚪ | `Finalize` | — |
| ⚪ | `Initialize` | — |

</details>

<details>
<summary>🟢 <code>RFLX.Unsuback</code> — 2/2 subprograms · 2/2 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟡 <code>RFLX.Unsuback.Packet</code> — 52/53 subprograms · 307/308 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Internal` | 7/7 |
| 🟢 | `Field_First_Packet_Identifier` | 2/2 |
| 🟢 | `Field_First_Packet_Type` | 2/2 |
| 🟢 | `Field_First_Remaining_Length` | 2/2 |
| 🟢 | `Field_First_Reserved` | 2/2 |
| 🟢 | `Field_Last` | 4/4 |
| 🟢 | `Field_Size` | 2/2 |
| 🟢 | `Field_Size_Internal` | 2/2 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Packet_Identifier` | 1/1 |
| 🟢 | `Get_Packet_Type` | 1/1 |
| 🟢 | `Get_Remaining_Length` | 1/1 |
| 🟢 | `Get_Reserved` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 34/34 |
| 🟢 | `Set_Packet_Type` | 9/9 |
| 🟢 | `Set_Remaining_Length` | 9/9 |
| 🟢 | `Set_Reserved` | 9/9 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 7/7 |
| 🟢 | `To_Structure` | 6/6 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 11/11 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 21/21 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Packet_Identifier` | 11/12 |

</details>

<details>
<summary>🟢 <code>RFLX.Unsubscribe</code> — 2/2 subprograms · 2/2 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟡 <code>RFLX.Unsubscribe.Packet</code> — 57/58 subprograms · 428/429 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Complete_Topic_Filters` | 1/1 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Equal` | 16/16 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Internal` | 8/8 |
| 🟢 | `Field_First_Packet_Identifier` | 2/2 |
| 🟢 | `Field_First_Packet_Type` | 2/2 |
| 🟢 | `Field_First_Remaining_Length` | 2/2 |
| 🟢 | `Field_First_Reserved` | 2/2 |
| 🟢 | `Field_First_Topic_Filters` | 2/2 |
| 🟢 | `Field_Last` | 6/6 |
| 🟢 | `Field_Size` | 4/4 |
| 🟢 | `Field_Size_Internal` | 3/3 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Packet_Identifier` | 1/1 |
| 🟢 | `Get_Packet_Type` | 1/1 |
| 🟢 | `Get_Remaining_Length` | 1/1 |
| 🟢 | `Get_Reserved` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialize_Topic_Filters` | 15/15 |
| 🟢 | `Initialize_Topic_Filters_Private` | 23/23 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 35/35 |
| 🟢 | `Set_Packet_Type` | 9/9 |
| 🟢 | `Set_Remaining_Length` | 10/10 |
| 🟢 | `Set_Reserved` | 9/9 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Set_Topic_Filters` | 22/22 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Switch_To_Topic_Filters` | 26/26 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `Update_Topic_Filters` | 17/17 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 12/12 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 24/24 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Packet_Identifier` | 12/13 |

</details>

<details>
<summary>🟢 <code>RFLX.Unsubscribe.Topic_Filter_List</code> — 13/13 subprograms · 96/96 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Append_Element` | 11/11 |
| 🟢 | `Available_Space` | 1/1 |
| 🟢 | `Context` | 2/2 |
| 🟢 | `Contextpredicate` | 5/5 |
| 🟢 | `Copy` | 9/9 |
| 🟢 | `Data` | 9/9 |
| 🟢 | `Initialize` | 11/11 |
| 🟢 | `Initialize` | 17/17 |
| 🟢 | `Reset` | 3/3 |
| 🟢 | `Size` | 1/1 |
| 🟢 | `Switch` | 7/7 |
| 🟢 | `Take_Buffer` | 6/6 |
| 🟢 | `Update` | 14/14 |

</details>

<details>
<summary>🟢 <code>RFLX.Window_Update</code> — 2/2 subprograms · 2/2 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `To_Actual` | 1/1 |
| 🟢 | `To_Actual` | 1/1 |

</details>

<details>
<summary>🟡 <code>RFLX.Window_Update.Packet</code> — 46/47 subprograms · 273/274 VCs (100%)</summary>

| | Subprogram | VCs |
|---|---|---:|
| 🟢 | `Available_Space` | 2/2 |
| 🟢 | `Buffer_Length` | 2/2 |
| 🟢 | `Buffer_Size` | 2/2 |
| 🟢 | `Context` | 3/3 |
| 🟢 | `Copy` | 10/10 |
| 🟢 | `Cursors_Invariant` | 1/1 |
| 🟢 | `Data` | 6/6 |
| 🟢 | `Field_Condition` | 2/2 |
| 🟢 | `Field_First` | 3/3 |
| 🟢 | `Field_First_Internal` | 5/5 |
| 🟢 | `Field_First_Reserved` | 2/2 |
| 🟢 | `Field_First_Window_Size_Increment` | 2/2 |
| 🟢 | `Field_Last` | 4/4 |
| 🟢 | `Field_Size` | 2/2 |
| 🟢 | `Field_Size_Internal` | 2/2 |
| 🟢 | `Get` | 10/10 |
| 🟢 | `Get_Reserved` | 1/1 |
| 🟢 | `Get_Window_Size_Increment` | 1/1 |
| 🟢 | `Incomplete_Message` | 1/1 |
| 🟢 | `Initialize` | 16/16 |
| 🟢 | `Initialize` | 18/18 |
| 🟢 | `Initialized` | 4/4 |
| 🟢 | `Read` | 4/4 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset` | 6/6 |
| 🟢 | `Reset_Dependent_Fields` | 14/14 |
| 🟢 | `Set` | 34/34 |
| 🟢 | `Set_Reserved` | 7/7 |
| 🟢 | `Set_Scalar` | 21/21 |
| 🟢 | `Size` | 3/3 |
| 🟢 | `Sufficient_Buffer_Length` | 5/5 |
| 🟢 | `Sufficient_Buffer_Length` | 1/1 |
| 🟢 | `Sufficient_Space` | 2/2 |
| 🟢 | `Take_Buffer` | 8/8 |
| 🟢 | `To_Context` | 5/5 |
| 🟢 | `To_Structure` | 4/4 |
| 🟢 | `Valid` | 1/1 |
| 🟢 | `Valid_Context` | 11/11 |
| 🟢 | `Valid_Length` | 2/2 |
| 🟢 | `Valid_Next` | 1/1 |
| 🟢 | `Valid_Next_Internal` | 2/2 |
| 🟢 | `Valid_Predecessors_Invariant` | 1/1 |
| 🟢 | `Valid_Size` | 1/1 |
| 🟢 | `Valid_Value` | 1/1 |
| 🟢 | `Verify` | 21/21 |
| 🟢 | `Verify_Message` | 4/4 |
| 🟡 | `Set_Window_Size_Increment` | 9/10 |

</details>

</details>
