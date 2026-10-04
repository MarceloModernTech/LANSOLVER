#Requires -Version 5.1
<#
.SYNOPSIS
    Diagnostico completo do "System error 86" (ERROR_INVALID_PASSWORD / 0x56) em SMB.

.DESCRIPTION
    Verifica os 6 vetores descritos no relatorio "SMB Windows - Erro 86":
      I   - Credenciais locais, cofre, PIN do Windows Hello, conta bloqueada/expirada/sem senha
      II  - LmCompatibilityLevel / NTLM (cliente e servidor)
      III - UAC remoto (LocalAccountTokenFilterPolicy) em compartilhamentos administrativos
      IV  - Transporte (DNS, porta 445), Azure File Share, Hybrid Join, UPN
      V   - Canal seguro/SID duplicado, sincronismo de horario (Kerberos), fallback NTLM
      VI  - Credential Guard/VBS + nome de usuario com caracteres nao-latinos
    REDE BASICA (o "obvio"): perfil da rede (Privada/Publica), descoberta de rede,
    regra de firewall do SMB (445), servicos de descoberta, adaptador/APIPA/gateway,
    sub-rede do destino, ping, MAC duplicado no ARP, arquivo hosts, compartilhamentos
    existentes. Tambem: autenticacao de passagem (mesmo usuario nos 2 PCs), evento 6167
    (SID duplicado), eventos NTLM 8001-8006, protecao de loopback, TPM/Secure Boot,
    assinatura exigida + convidado (Windows 11 24H2).
    Alem disso: configuracao SMB (assinatura/criptografia/SMB1), eventos 4625,
    eventos SMBClient 30800/30803 e um TESTE ATIVO de autenticacao que mostra
    o codigo Win32 real devolvido (inclusive 86) para varios formatos de usuario.

    POR PADRAO o script NAO altera nada (somente leitura + uma conexao de teste em
    IPC$ que e desfeita logo em seguida).

    COM -Corrigir ele aplica, DEPOIS da verificacao, as correcoes seguras para o que
    foi encontrado (veja os parametros abaixo), grava um BACKUP em JSON dos valores
    anteriores, reverifica cada item e repete o teste ativo. Use -Simular para ver o
    que seria feito sem alterar nada, e -Restaurar <backup.json> para desfazer.

    Correcoes automaticas (-Corrigir):
      - LmCompatibilityLevel < 3  -> 3 (somente NTLMv2)
      - Servicos parados (LanmanWorkstation, w32time, Netlogon em dominio) -> Automatico + iniciar
      - Horario: w32tm /resync (em workgroup, configura servidores NTP se necessario)
      - Assinatura SMB do cliente desabilitada -> habilitada
      - forceguest=1 em workgroup -> 0 (modelo classico)
      - Credenciais salvas (cmdkey) do servidor alvo, sessoes conflitantes e mapeamentos quebrados
      - Cache DNS (quando o nome do servidor nao resolve)
      - Componentes do adaptador desabilitados (Cliente p/ Redes Microsoft, Compartilhamento de Arquivos)
      - Servicos de rede/descoberta parados (NlaSvc, fdPHost, FDResPub)
    Correcoes que exigem aceite explicito (opt-in):
      -PermitirAdminRemoto  LocalAccountTokenFilterPolicy=1 (REDUZ a seguranca; aplique no SERVIDOR)
      -CorrigirConta        habilita/desbloqueia/remove expiracao da conta LOCAL informada em -Usuario
      -ReparCanalSeguro     Test-ComputerSecureChannel -Repair (precisa de -CredencialDominio)
      -AjustarRede          rede Publica -> Privada + habilita regras de firewall de Compartilhamento e
                            Descoberta de Rede (AUMENTA a exposicao: use so em rede confiavel)
      -DefinirRedePrivada   perfil de rede Publico -> Privado
      -HabilitarCompartilhamento  firewall do SMB + descoberta de rede (so perfis Privado/Dominio)
      -PermitirConvidadoInseguro / -RelaxarAssinaturaCliente  (reduzem a seguranca)
    Nunca e alterado automaticamente: bloqueio de NTLM por GPO, Credential Guard, SID duplicado,
    senhas e contas do AD (apenas listados como PENDENTE com a orientacao).

.PARAMETER Servidor
    Nome, FQDN ou IP do servidor/compartilhamento de destino (ex.: SRV01, nas.local,
    conta.file.core.windows.net). Se omitido, so avalia esta maquina.

.PARAMETER Compartilhamento
    Compartilhamento usado no teste ativo. Padrao: IPC$.

.PARAMETER Usuario
    Usuario que esta falhando (DOMINIO\usuario, SERVIDOR\usuario, .\usuario ou usuario@dominio).

.PARAMETER Credencial
    PSCredential para o teste ativo. Ex.: -Credencial (Get-Credential)

.PARAMETER TentarRemoto
    Tambem consulta o servidor via WinRM (Invoke-Command) para comparar politicas,
    horario, SID e estado da conta local. Requer WinRM habilitado no servidor.

.PARAMETER CredencialRemota
    Credencial administrativa para o WinRM (se diferente da sessao atual).

.PARAMETER HorasEventos
    Janela (em horas) para analisar eventos. Padrao: 24.

.PARAMETER Corrigir
    Aplica as correcoes seguras apos o diagnostico. Se nao estiver como Administrador,
    o script se reabre elevado (UAC) automaticamente.

.PARAMETER Simular
    Mostra o que seria corrigido, sem alterar nada (implica -Corrigir).

.PARAMETER PermitirAdminRemoto
    Define LocalAccountTokenFilterPolicy=1 nesta maquina (use no servidor de destino).

.PARAMETER CorrigirConta
    Corrige a conta LOCAL de -Usuario nesta maquina (habilitar, desbloquear, sem expiracao).

.PARAMETER ReparCanalSeguro
    Repara o canal seguro do dominio (requer -CredencialDominio).

.PARAMETER DefinirRedePrivada
    Muda conexoes de rede PUBLICAS para PRIVADAS (use somente em rede confiavel).

.PARAMETER HabilitarCompartilhamento
    Habilita, apenas nos perfis Privado/Dominio ativos, a regra de entrada do SMB (445),
    o grupo Descoberta de Rede e os servicos fdPHost/FDResPub. Nunca habilita em rede Publica.

.PARAMETER PermitirConvidadoInseguro
    AllowInsecureGuestAuth=1 (acesso de convidado a NAS/TV sem senha). REDUZ a seguranca.

.PARAMETER RelaxarAssinaturaCliente
    RequireSecuritySignature=0 no cliente (assinatura continua habilitada, so deixa de ser
    obrigatoria). REDUZ a seguranca; use para falar com dispositivos que nao assinam.

.PARAMETER AjustarRede
    Muda conexoes de rede Publicas para Privadas e habilita as regras de firewall de
    Descoberta de Rede e Compartilhamento de Arquivos (perfis Private/Domain). Nunca use em
    rede publica (cafe, hotel, aeroporto).

.PARAMETER CredencialDominio
    Credencial de dominio com direito de reparar o canal seguro.

.PARAMETER ServidoresNtp
    Servidores NTP (separados por virgula) usados SOMENTE em workgroup quando o resync falhar.
    Padrao: a.ntp.br,b.ntp.br,time.windows.com

.PARAMETER Restaurar
    Caminho de um Backup_Erro86_*.json: desfaz as alteracoes registradas nele e sai.

.PARAMETER PedirCredencial
    Pede a credencial do teste ativo via Get-Credential (usado no reinicio elevado).

.PARAMETER Relatorio
    Caminho do .txt de saida. Padrao: pasta atual.

.EXAMPLE
    # So esta maquina
    .\Diagnostico-Erro86.ps1

.EXAMPLE
    # Completo, executado como administrador
    .\Diagnostico-Erro86.ps1 -Servidor SRV01 -Usuario SRV01\joao -Credencial (Get-Credential) -TentarRemoto

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Diagnostico-Erro86.ps1 -Servidor 192.168.0.10

.EXAMPLE
    # 1) ver o que seria corrigido  2) corrigir  3) desfazer, se necessario
    .\Diagnostico-Erro86.ps1 -Servidor SRV01 -Usuario SRV01\joao -Simular
    .\Diagnostico-Erro86.ps1 -Servidor SRV01 -Usuario SRV01\joao -Corrigir
    .\Diagnostico-Erro86.ps1 -Restaurar .\Backup_Erro86_20261003_235959.json
#>
[CmdletBinding()]
param(
    [string]$Servidor,
    [string]$Compartilhamento = 'IPC$',
    [string]$Usuario,
    [pscredential]$Credencial,
    [switch]$TentarRemoto,
    [pscredential]$CredencialRemota,
    [int]$HorasEventos = 24,
    [switch]$Corrigir,
    [switch]$Simular,
    [switch]$PermitirAdminRemoto,
    [switch]$CorrigirConta,
    [switch]$ReparCanalSeguro,
    [switch]$AjustarRede,
    [switch]$DefinirRedePrivada,
    [switch]$HabilitarCompartilhamento,
    [switch]$PermitirConvidadoInseguro,
    [switch]$RelaxarAssinaturaCliente,
    [pscredential]$CredencialDominio,
    [string]$ServidoresNtp = 'a.ntp.br,b.ntp.br,time.windows.com',
    [string]$Restaurar,
    [switch]$PedirCredencial,
    [string]$Relatorio = (Join-Path (Get-Location).Path ("Diagnostico_Erro86_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss')))
)

$ErrorActionPreference = 'Continue'
$script:Resultados = New-Object System.Collections.Generic.List[object]
$script:Correcoes = New-Object System.Collections.Generic.List[object]
$script:Backup = New-Object System.Collections.Generic.List[object]
$script:Fase = 'diag'
$script:ServicosParados = @()
$script:CredRelacionadas = @()
$script:MapsRuins = @()
$script:SessaoConflito = $false
$script:InfoContaLocal = $null
$script:CanalOk = $null
$script:DnsFalhou = $false
$script:PerfisPublicos = @()
$script:ServDescoberta = @()

# ----------------------------------------------------------------------------
# Funcoes auxiliares
# ----------------------------------------------------------------------------
function Titulo {
    param([string]$Texto)
    Write-Host ''
    Write-Host ('=== {0} ===' -f $Texto) -ForegroundColor White
}

function Add-Resultado {
    param(
        [string]$Vetor,
        [string]$Item,
        [ValidateSet('OK', 'ALERTA', 'FALHA', 'INFO')][string]$Status,
        [string]$Detalhe,
        [string]$Correcao = ''
    )
    $script:Resultados.Add([pscustomobject]@{
            Fase = $script:Fase; Vetor = $Vetor; Item = $Item; Status = $Status; Detalhe = $Detalhe
            Correcao = $(if ($Status -eq 'ALERTA' -or $Status -eq 'FALHA') { $Correcao } else { '' })
        })
    $cor = switch ($Status) { 'OK' { 'Green' } 'ALERTA' { 'Yellow' } 'FALHA' { 'Red' } default { 'Cyan' } }
    Write-Host ('[{0,-6}] {1}: {2}' -f $Status, $Item, $Detalhe) -ForegroundColor $cor
    if ($Correcao -and ($Status -eq 'ALERTA' -or $Status -eq 'FALHA')) {
        Write-Host ('         -> {0}' -f $Correcao) -ForegroundColor DarkGray
    }
}

function Get-RegValor {
    param([string]$Caminho, [string]$Nome)
    try { (Get-ItemProperty -Path $Caminho -Name $Nome -ErrorAction Stop).$Nome } catch { $null }
}

function Test-Porta {
    param([string]$Alvo, [int]$Porta, [int]$TimeoutMs = 3000)
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect($Alvo, $Porta, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs) -and $c.Connected) { $c.EndConnect($iar); return $true }
        return $false
    }
    catch { return $false }
    finally { $c.Close() }
}

function Test-NaoAscii {
    param([string]$Texto)
    if ([string]::IsNullOrEmpty($Texto)) { return $false }
    return ($Texto -match '[^\x00-\x7F]')
}

function Split-Usuario {
    param([string]$Valor)
    $r = [ordered]@{ Dominio = ''; Nome = $Valor; Formato = 'simples' }
    if ($Valor -match '^(?<d>[^\\]+)\\(?<n>.+)$') { $r.Dominio = $Matches.d; $r.Nome = $Matches.n; $r.Formato = 'DOMINIO\usuario' }
    elseif ($Valor -match '^(?<n>[^@]+)@(?<d>.+)$') { $r.Dominio = $Matches.d; $r.Nome = $Matches.n; $r.Formato = 'UPN' }
    [pscustomobject]$r
}

function Get-Dsreg {
    param([string]$Nome)
    $l = $script:DsregSaida | Select-String -Pattern ('^\s*{0}\s*:\s*(.+)$' -f [regex]::Escape($Nome)) | Select-Object -First 1
    if ($l) { $l.Matches[0].Groups[1].Value.Trim() }
}

function Get-DesvioHorario {
    param([string]$Alvo)
    try {
        $saida = & w32tm /stripchart /computer:$Alvo /samples:1 /dataonly 2>&1 | Out-String
        $m = [regex]::Matches($saida, '([+-]\d+[\.,]\d+)s')
        if ($m.Count -gt 0) { return [double]($m[$m.Count - 1].Groups[1].Value -replace ',', '.') }
    }
    catch { }
    return $null
}

function Get-InfoUsuarioLocal {
    param([string]$Nome)
    $o = [ordered]@{ Nome = $Nome; Existe = $false }
    try {
        $f = "LocalAccount=True AND Name='{0}'" -f $Nome.Replace("'", "''")
        $u = Get-CimInstance -ClassName Win32_UserAccount -Filter $f -ErrorAction Stop
        if ($u) {
            $o.Existe = $true
            $o.Desabilitada = [bool]$u.Disabled
            $o.Bloqueada = [bool]$u.Lockout
            $o.SenhaObrigatoria = [bool]$u.PasswordRequired
            $o.SenhaExpira = [bool]$u.PasswordExpires
            $o.SID = [string]$u.SID
        }
    }
    catch { }
    try {
        $l = Get-LocalUser -Name $Nome -ErrorAction Stop
        $o.ContaExpiraEm = $l.AccountExpires
        $o.SenhaExpiraEm = $l.PasswordExpires
        $o.UltimaTrocaSenha = $l.PasswordLastSet
    }
    catch { }
    [pscustomobject]$o
}

function Get-InfoUsuarioAD {
    param([string]$Nome)
    try {
        $filtro = '(&(objectCategory=person)(objectClass=user)(sAMAccountName={0}))' -f $Nome
        $s = [adsisearcher]$filtro
        [void]$s.PropertiesToLoad.AddRange(@('useraccountcontrol', 'msds-user-account-control-computed', 'accountexpires', 'userprincipalname', 'pwdlastset'))
        $r = $s.FindOne()
        if (-not $r) { return $null }
        $uac = [int]$r.Properties['useraccountcontrol'][0]
        $comp = 0
        if ($r.Properties['msds-user-account-control-computed'].Count -gt 0) { $comp = [int]$r.Properties['msds-user-account-control-computed'][0] }
        $exp = $null
        if ($r.Properties['accountexpires'].Count -gt 0) {
            $v = [int64]$r.Properties['accountexpires'][0]
            if ($v -ne 0 -and $v -ne 9223372036854775807) { $exp = [datetime]::FromFileTimeUtc($v) }
        }
        $pwdSet = 1
        if ($r.Properties['pwdlastset'].Count -gt 0) { $pwdSet = [int64]$r.Properties['pwdlastset'][0] }
        [pscustomobject]@{
            UPN             = [string]$r.Properties['userprincipalname'][0]
            Desabilitada    = [bool]($uac -band 0x2)
            Bloqueada       = [bool](($comp -band 0x10) -or ($uac -band 0x10))
            SenhaExpirada   = [bool]($comp -band 0x800000)
            SenhaNaoExigida = [bool]($uac -band 0x20)
            TrocarNoLogon   = ($pwdSet -eq 0)
            ContaExpiraEm   = $exp
        }
    }
    catch { $null }
}

function Test-AdminLocalNaoRid500 {
    param([string]$Nome)
    try {
        $m = Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop |
            Where-Object { $_.Name -match ('(^|\\){0}$' -f [regex]::Escape($Nome)) } | Select-Object -First 1
        if ($m) { return (-not ($m.SID.Value -like '*-500')) }
    }
    catch { }
    return $false
}

function Write-ResultadoUsuarioLocal {
    param($Info, [string]$Onde, [string]$Vetor = 'I')
    if (-not $Info.Existe) {
        Add-Resultado $Vetor "Conta local '$($Info.Nome)' em $Onde" 'INFO' 'nao e uma conta local desse computador'
        return
    }
    $problema = $false
    if ($Info.Desabilitada) { $problema = $true; Add-Resultado $Vetor "Conta '$($Info.Nome)' em $Onde" 'FALHA' 'conta DESABILITADA' "Enable-LocalUser -Name '$($Info.Nome)'" }
    if ($Info.Bloqueada) { $problema = $true; Add-Resultado $Vetor "Conta '$($Info.Nome)' em $Onde" 'FALHA' 'conta BLOQUEADA (lockout)' 'Desbloqueie em lusrmgr.msc ou: net user <usuario> /active:yes' }
    if ($Info.ContaExpiraEm -and $Info.ContaExpiraEm -lt (Get-Date)) { $problema = $true; Add-Resultado $Vetor "Conta '$($Info.Nome)' em $Onde" 'FALHA' "conta EXPIROU em $($Info.ContaExpiraEm)" 'Defina nova data: Set-LocalUser -AccountNeverExpires' }
    if ($Info.SenhaExpiraEm -and $Info.SenhaExpiraEm -lt (Get-Date)) { $problema = $true; Add-Resultado $Vetor "Conta '$($Info.Nome)' em $Onde" 'FALHA' "SENHA expirou em $($Info.SenhaExpiraEm)" 'Redefina a senha da conta' }
    if ($Info.SenhaObrigatoria -eq $false) { $problema = $true; Add-Resultado $Vetor "Conta '$($Info.Nome)' em $Onde" 'ALERTA' 'conta sem senha obrigatoria (logon de rede com senha em branco e bloqueado por padrao)' "Defina uma senha real: net user $($Info.Nome) *" }
    if (-not $problema) { Add-Resultado $Vetor "Conta '$($Info.Nome)' em $Onde" 'OK' 'habilitada, nao bloqueada, sem expiracao detectada' }
}

# ----------------------------------------------------------------------------
# Funcoes de correcao / backup / restauracao
# ----------------------------------------------------------------------------
function Get-PerfisFwAtivos {
    param([switch]$SemPublico)
    $out = @()
    try {
        foreach ($c in (Get-NetConnectionProfile -ErrorAction Stop)) {
            switch ($c.NetworkCategory.ToString()) {
                'Private' { $out += 'Private' }
                'DomainAuthenticated' { $out += 'Domain' }
                'Public' { if (-not $SemPublico) { $out += 'Public' } }
            }
        }
    }
    catch { }
    @($out | Select-Object -Unique)
}

function Get-RegrasFw {
    # regras de ENTRADA do grupo "Descoberta de Rede" (id de recurso independe do idioma)
    $r = @()
    try { $r = @(Get-NetFirewallRule -Group '@FirewallAPI.dll,-32752' -Direction Inbound -ErrorAction Stop) } catch { }
    if ($r.Count -eq 0) {
        try { $r = @(Get-NetFirewallRule -Direction Inbound -ErrorAction Stop | Where-Object { $_.DisplayGroup -match 'Network Discovery|Descoberta de Rede' }) } catch { }
    }
    $r
}

function Test-RegraAtivaNoPerfil {
    param($Regra, [string[]]$Perfis)
    if ($null -eq $Regra) { return $false }
    if ($Regra.Enabled.ToString() -ne 'True' -or $Regra.Action.ToString() -ne 'Allow') { return $false }
    $p = $Regra.Profile.ToString()
    if ($p -match 'Any') { return $true }
    foreach ($x in $Perfis) { if ($p -match $x) { return $true } }
    return $false
}

function ConvertTo-UInt32Ip {
    param([string]$Ip)
    $by = [System.Net.IPAddress]::Parse($Ip).GetAddressBytes()
    [Array]::Reverse($by)
    [int64][BitConverter]::ToUInt32($by, 0)
}

function Test-MesmaSubrede {
    param([string]$A, [string]$B, [int]$Prefixo)
    $m = [int64]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $Prefixo))
    ((ConvertTo-UInt32Ip $A) -band $m) -eq ((ConvertTo-UInt32Ip $B) -band $m)
}

function Save-Backup {
    try {
        ConvertTo-Json -InputObject @($script:Backup.ToArray()) -Depth 4 | Out-File -FilePath $BackupPath -Encoding UTF8
    }
    catch { }
}

function Backup-Reg {
    param([string]$Caminho, [string]$Nome)
    $existia = $false; $valor = $null; $tipo = $null
    try {
        $k = Get-Item -Path $Caminho -ErrorAction Stop
        if ($k.GetValueNames() -contains $Nome) {
            $existia = $true
            $valor = $k.GetValue($Nome)
            $tipo = $k.GetValueKind($Nome).ToString()
        }
    }
    catch { }
    $script:Backup.Add([pscustomobject]@{ Tipo = 'Registro'; Caminho = $Caminho; Nome = $Nome; Existia = $existia; Valor = $valor; TipoValor = $tipo })
    Save-Backup
}

function Set-RegDword {
    param([string]$Caminho, [string]$Nome, [int]$Valor)
    Backup-Reg $Caminho $Nome
    if (-not (Test-Path $Caminho)) { New-Item -Path $Caminho -Force | Out-Null }
    New-ItemProperty -Path $Caminho -Name $Nome -Value $Valor -PropertyType DWord -Force | Out-Null
}

function Backup-Servico {
    param([string]$Nome)
    $w = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $Nome) -ErrorAction SilentlyContinue
    if ($w) {
        $script:Backup.Add([pscustomobject]@{ Tipo = 'Servico'; Nome = $Nome; Modo = $w.StartMode; EstavaRodando = ($w.State -eq 'Running') })
        Save-Backup
    }
}

function Add-Correcao {
    param(
        [string]$Vetor,
        [string]$Item,
        [ValidateSet('CORRIGIDO', 'SIMULADO', 'NAO-VERIFICADO', 'FALHOU', 'MANUAL')][string]$Status,
        [string]$Detalhe
    )
    $script:Correcoes.Add([pscustomobject]@{ Vetor = $Vetor; Item = $Item; Status = $Status; Detalhe = $Detalhe })
    $cor = switch ($Status) { 'CORRIGIDO' { 'Green' } 'SIMULADO' { 'Cyan' } 'FALHOU' { 'Red' } default { 'Yellow' } }
    Write-Host ('[{0,-14}] {1}: {2}' -f $Status, $Item, $Detalhe) -ForegroundColor $cor
}

function Invoke-Correcao {
    param([string]$Vetor, [string]$Item, [string]$Descricao, [scriptblock]$Acao, [scriptblock]$Verificar)
    if ($Simular) { Add-Correcao $Vetor $Item 'SIMULADO' $Descricao; return }
    try {
        & $Acao | Out-Null
        $okv = $true
        if ($Verificar) { $okv = [bool](& $Verificar) }
        if ($okv) { Add-Correcao $Vetor $Item 'CORRIGIDO' $Descricao }
        else { Add-Correcao $Vetor $Item 'NAO-VERIFICADO' ("{0} (aplicado, mas a releitura nao confirmou)" -f $Descricao) }
    }
    catch { Add-Correcao $Vetor $Item 'FALHOU' ("{0}: {1}" -f $Descricao, $_.Exception.Message) }
}

function Invoke-HabilitarRegras {
    param([string]$Item, $Regras)
    $Regras = @($Regras)
    if ($Regras.Count -eq 0) { return }
    $nomes = @($Regras | ForEach-Object { $_.Name })
    Invoke-Correcao 'Basico' $Item ("habilitar {0} regra(s) de firewall (perfis Private/Domain)" -f $nomes.Count) {
        foreach ($n in $nomes) { $script:Backup.Add([pscustomobject]@{ Tipo = 'RegraFirewall'; Nome = $n; Enabled = $false }) }
        Save-Backup
        Enable-NetFirewallRule -Name $nomes -ErrorAction Stop
    } {
        @(Get-NetFirewallRule -Name $nomes -ErrorAction SilentlyContinue | Where-Object { [string]$_.Enabled -ne 'True' }).Count -eq 0
    }
}

function Invoke-Restauracao {
    param([string]$Arquivo)
    if (-not (Test-Path $Arquivo)) { Write-Host "Backup nao encontrado: $Arquivo" -ForegroundColor Red; return }
    $bruto = Get-Content -Path $Arquivo -Raw -Encoding UTF8 | ConvertFrom-Json
    $itens = @($bruto)
    [array]::Reverse($itens)
    Write-Host ("Restaurando {0} item(ns) de {1}" -f $itens.Count, $Arquivo) -ForegroundColor White
    foreach ($i in $itens) {
        try {
            switch ($i.Tipo) {
                'Registro' {
                    if ($Simular) { Write-Host ("[SIMULADO] registro {0}\{1}" -f $i.Caminho, $i.Nome) -ForegroundColor Cyan; break }
                    if ($i.Existia) {
                        if (-not (Test-Path $i.Caminho)) { New-Item -Path $i.Caminho -Force | Out-Null }
                        New-ItemProperty -Path $i.Caminho -Name $i.Nome -Value $i.Valor -PropertyType $i.TipoValor -Force | Out-Null
                        Write-Host ("[RESTAURADO] {0}\{1} = {2}" -f $i.Caminho, $i.Nome, $i.Valor) -ForegroundColor Green
                    }
                    else {
                        Remove-ItemProperty -Path $i.Caminho -Name $i.Nome -ErrorAction SilentlyContinue
                        Write-Host ("[RESTAURADO] {0}\{1} removido (nao existia antes)" -f $i.Caminho, $i.Nome) -ForegroundColor Green
                    }
                }
                'Servico' {
                    if ($Simular) { Write-Host ("[SIMULADO] servico {0}" -f $i.Nome) -ForegroundColor Cyan; break }
                    $modo = switch ($i.Modo) { 'Auto' { 'Automatic' } 'Disabled' { 'Disabled' } default { 'Manual' } }
                    Set-Service -Name $i.Nome -StartupType $modo -ErrorAction Stop
                    if (-not $i.EstavaRodando) { Stop-Service -Name $i.Nome -Force -ErrorAction SilentlyContinue }
                    Write-Host ("[RESTAURADO] servico {0}: inicializacao {1}, rodando={2}" -f $i.Nome, $modo, $i.EstavaRodando) -ForegroundColor Green
                }
                'PerfilRede' {
                    if ($Simular) { Write-Host ("[SIMULADO] perfil de rede interface {0}" -f $i.InterfaceIndex) -ForegroundColor Cyan; break }
                    Set-NetConnectionProfile -InterfaceIndex $i.InterfaceIndex -NetworkCategory $i.Categoria -ErrorAction Stop
                    Write-Host ("[RESTAURADO] interface {0}: perfil de rede = {1}" -f $i.InterfaceIndex, $i.Categoria) -ForegroundColor Green
                }
                'FirewallRegra' {
                    if ($Simular) { Write-Host ("[SIMULADO] regra de firewall {0}" -f $i.Nome) -ForegroundColor Cyan; break }
                    $perf = @($i.Perfil -split ',\s*')
                    Set-NetFirewallRule -Name $i.Nome -Enabled $i.Habilitada -Profile $perf -ErrorAction Stop
                    Write-Host ("[RESTAURADO] regra {0}: Enabled={1} Profile={2}" -f $i.Nome, $i.Habilitada, $i.Perfil) -ForegroundColor Green
                }
                'SmbClientSign' {
                    if ($Simular) { Write-Host '[SIMULADO] assinatura SMB do cliente' -ForegroundColor Cyan; break }
                    Set-SmbClientConfiguration -EnableSecuritySignature ([bool]$i.Valor) -Force -Confirm:$false
                    Write-Host ("[RESTAURADO] EnableSecuritySignature = {0}" -f $i.Valor) -ForegroundColor Green
                }
                'Binding' {
                    if ($Simular) { Write-Host ("[SIMULADO] binding {0} em {1}" -f $i.Id, $i.Adaptador) -ForegroundColor Cyan; break }
                    if ($i.Enabled) { Enable-NetAdapterBinding -Name $i.Adaptador -ComponentID $i.Id -ErrorAction Stop }
                    else { Disable-NetAdapterBinding -Name $i.Adaptador -ComponentID $i.Id -ErrorAction Stop }
                    Write-Host ("[RESTAURADO] binding {0} em {1}: habilitado={2}" -f $i.Id, $i.Adaptador, $i.Enabled) -ForegroundColor Green
                }
                'RegraFirewall' {
                    if ($Simular) { Write-Host ("[SIMULADO] regra de firewall {0}" -f $i.Nome) -ForegroundColor Cyan; break }
                    $en = if ($i.Enabled) { 'True' } else { 'False' }
                    Set-NetFirewallRule -Name $i.Nome -Enabled $en -ErrorAction Stop
                    Write-Host ("[RESTAURADO] regra {0}: Enabled={1}" -f $i.Nome, $en) -ForegroundColor Green
                }
                'PerfilRede' {
                    if ($Simular) { Write-Host ("[SIMULADO] perfil de rede (interface {0})" -f $i.Indice) -ForegroundColor Cyan; break }
                    Set-NetConnectionProfile -InterfaceIndex $i.Indice -NetworkCategory $i.Categoria -ErrorAction Stop
                    Write-Host ("[RESTAURADO] interface {0}: categoria {1}" -f $i.Indice, $i.Categoria) -ForegroundColor Green
                }
            }
        }
        catch { Write-Host ("[FALHOU] {0} {1}: {2}" -f $i.Tipo, $i.Nome, $_.Exception.Message) -ForegroundColor Red }
    }
    Write-Host 'Observacao: credenciais removidas do cofre (cmdkey) e conexoes de rede encerradas nao sao restauraveis.' -ForegroundColor DarkGray
}

# ----------------------------------------------------------------------------
# Inicio
# ----------------------------------------------------------------------------
$ehAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($Simular) { $Corrigir = $true }
$pastaSaida = Split-Path -Parent $Relatorio
if (-not $pastaSaida) { $pastaSaida = (Get-Location).Path; $Relatorio = Join-Path $pastaSaida $Relatorio }
$BackupPath = Join-Path $pastaSaida ("Backup_Erro86_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

# Correcoes e restauracao exigem Administrador: reabre elevado (UAC) se preciso
if ((($Corrigir -and -not $Simular) -or $Restaurar) -and -not $ehAdmin) {
    if ($CredencialDominio -or $CredencialRemota) {
        Write-Host 'Para usar -CredencialDominio/-CredencialRemota abra o PowerShell como Administrador e execute novamente.' -ForegroundColor Red
        exit 1
    }
    if (-not $PSCommandPath) { Write-Host 'Salve o script em arquivo .ps1 e execute novamente como Administrador.' -ForegroundColor Red; exit 1 }
    Write-Host 'Correcoes exigem Administrador. Reabrindo elevado (confirme o UAC)...' -ForegroundColor Yellow
    $partes = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', ('"{0}"' -f $PSCommandPath))
    foreach ($k in $PSBoundParameters.Keys) {
        $v = $PSBoundParameters[$k]
        if ($v -is [pscredential]) { continue }
        if ($v -is [switch]) { if ($v.IsPresent) { $partes += "-$k" }; continue }
        $partes += "-$k"
        $partes += ('"{0}"' -f ([string]$v).Replace('"', '\"'))
    }
    if (-not $PSBoundParameters.ContainsKey('Relatorio')) { $partes += '-Relatorio'; $partes += ('"{0}"' -f $Relatorio) }
    if ($Credencial) { $partes += '-PedirCredencial' }
    try { Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $partes }
    catch { Write-Host "Elevacao cancelada/falhou: $($_.Exception.Message)" -ForegroundColor Red }
    exit
}

if ($Restaurar) { Invoke-Restauracao $Restaurar; exit }

if ($PedirCredencial) {
    try { $Credencial = Get-Credential -Message 'Credencial para o teste ativo de autenticacao (nao e gravada)' } catch { }
}

if ($Servidor) { $Servidor = ($Servidor -replace '^\\\\', '') -replace '\\.*$', '' }
if (-not $Usuario -and $Credencial) { $Usuario = $Credencial.UserName }
$uInfo = $null
if ($Usuario) { $uInfo = Split-Usuario $Usuario }

$servidorLocal = $false
if ($Servidor) {
    $servidorLocal = ($Servidor -in @('localhost', '127.0.0.1', '::1', '.', $env:COMPUTERNAME)) -or ($Servidor -like "$env:COMPUTERNAME.*")
    if (-not $servidorLocal) {
        try { $ipsLocais = @(Get-NetIPAddress -ErrorAction Stop | ForEach-Object { $_.IPAddress }); $servidorLocal = ($ipsLocais -contains $Servidor) } catch { }
    }
}
$servidorEhIP = $false
if ($Servidor) { $tmpIp = $null; $servidorEhIP = [System.Net.IPAddress]::TryParse($Servidor, [ref]$tmpIp) }
$compAdmin = ($Compartilhamento -match '^(ADMIN\$|[A-Za-z]\$)$')

Write-Host ''
Write-Host 'DIAGNOSTICO DO ERRO 86 (ERROR_INVALID_PASSWORD / 0x56) - SMB' -ForegroundColor White
Write-Host ('Data: {0}   Alvo: {1}   Usuario: {2}' -f (Get-Date), $(if ($Servidor) { $Servidor } else { '(somente esta maquina)' }), $(if ($Usuario) { $Usuario } else { '(nao informado)' }))
if (-not $ehAdmin) {
    Write-Host 'AVISO: nao esta como Administrador. Eventos de seguranca, Get-SmbServerConfiguration e Test-ComputerSecureChannel podem ficar limitados.' -ForegroundColor Yellow
}

# ----------------------------------------------------------------------------
Titulo 'CONTEXTO'
# ----------------------------------------------------------------------------
$cs = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
$emDominio = [bool]$cs.PartOfDomain
$ondeTxt = if ($emDominio) { 'dominio ' + $cs.Domain } else { 'workgroup ' + $cs.Workgroup }
Add-Resultado 'Contexto' 'Sistema' 'INFO' ('{0} (build {1}) - {2}' -f $os.Caption, $os.BuildNumber, $ondeTxt)
Add-Resultado 'Contexto' 'Usuario atual' 'INFO' ('{0}\{1} | Administrador: {2}' -f $env:USERDOMAIN, $env:USERNAME, $ehAdmin)

$script:DsregSaida = @()
try { $script:DsregSaida = & dsregcmd /status 2>$null } catch { }

foreach ($svc in @('LanmanWorkstation', 'LanmanServer', 'Netlogon', 'w32time', 'NlaSvc')) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s) {
        if ($s.Status -ne 'Running') {
            if ($svc -eq 'Netlogon' -and -not $emDominio) {
                Add-Resultado 'Contexto' "Servico $svc" 'INFO' 'parado (normal em workgroup, nao se aplica)'
            }
            else {
                if ($svc -ne 'LanmanServer') { $script:ServicosParados += $svc }
                Add-Resultado 'Contexto' "Servico $svc" 'ALERTA' ("estado: {0}" -f $s.Status) "Start-Service $svc  (ou execute com -Corrigir)"
            }
        }
        else { Add-Resultado 'Contexto' "Servico $svc" 'OK' 'em execucao' }
    }
}

# ----------------------------------------------------------------------------
Titulo 'REDE - O BASICO (perfil, descoberta, firewall, adaptador, rota)'
# ----------------------------------------------------------------------------
$ini = (Get-Date).AddHours(-$HorasEventos)

# R.1 Perfil de rede (Publica bloqueia compartilhamento/descoberta de entrada)
$perfis = @()
try { $perfis = @(Get-NetConnectionProfile -ErrorAction Stop) } catch { }
if ($perfis.Count -eq 0) {
    Add-Resultado 'Rede' 'Perfil de rede' 'INFO' 'nenhuma conexao ativa encontrada (cabo/Wi-Fi desconectado?)'
}
foreach ($pf in $perfis) {
    $cat = $pf.NetworkCategory.ToString()
    if ($cat -eq 'Public') {
        $script:PerfisPublicos += $pf
        Add-Resultado 'Rede' 'Perfil de rede' 'ALERTA' ("'{0}' esta como PUBLICA: o Windows bloqueia compartilhamento de arquivos e descoberta de rede de ENTRADA" -f $pf.Name) 'Mude para Privada (Configuracoes > Rede e Internet > propriedades da conexao > Perfil de rede Privada) ou rode com -DefinirRedePrivada (somente em rede confiavel)'
    }
    elseif ($cat -eq 'Private') { Add-Resultado 'Rede' 'Perfil de rede' 'OK' ("'{0}': Privada" -f $pf.Name) }
    else { Add-Resultado 'Rede' 'Perfil de rede' 'INFO' ("'{0}': {1}" -f $pf.Name, $cat) }
}

# R.2 Firewall: perfis, regra do SMB (445) e descoberta de rede
$ativos = Get-PerfisFwAtivos
try {
    $fps = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { "{0}={1}" -f $_.Name, $_.Enabled })
    Add-Resultado 'Rede' 'Firewall do Windows' 'INFO' ($fps -join '  ')
}
catch { }
$temCompart = $false; $listaCompart = @()
try { $listaCompart = @(Get-SmbShare -Special $false -ErrorAction Stop); $temCompart = ($listaCompart.Count -gt 0) } catch { }
if ($temCompart) { Add-Resultado 'Rede' 'Compartilhamentos desta maquina' 'INFO' (($listaCompart | ForEach-Object { "{0} ({1})" -f $_.Name, $_.Path }) -join '; ') }
else { Add-Resultado 'Rede' 'Compartilhamentos desta maquina' 'INFO' 'nenhum compartilhamento criado (se outros PCs devem acessar este, falta compartilhar uma pasta)' }

if ($ativos.Count -eq 0) {
    Add-Resultado 'Rede' 'Regras de firewall (SMB/descoberta)' 'INFO' 'sem perfil de rede ativo para avaliar'
}
else {
    $regraSmb = $null
    try { $regraSmb = Get-NetFirewallRule -Name 'FPS-SMB-In-TCP' -ErrorAction Stop } catch { }
    if ($regraSmb) {
        if (Test-RegraAtivaNoPerfil $regraSmb $ativos) {
            Add-Resultado 'Rede' 'Compartilhamento de arquivos (firewall)' 'OK' ("regra de entrada SMB 445 ativa no perfil atual ({0})" -f ($ativos -join ','))
        }
        else {
            $sev = if ($temCompart) { 'ALERTA' } else { 'INFO' }
            Add-Resultado 'Rede' 'Compartilhamento de arquivos (firewall)' $sev ("regra de entrada SMB 445 desabilitada ou nao aplicada ao perfil atual ({0})" -f ($ativos -join ',')) 'Habilite "Compartilhamento de Arquivo e Impressora" para a rede Privada, ou rode com -HabilitarCompartilhamento'
        }
    }
    $rnd = @(Get-RegrasFw)
    if ($rnd.Count -gt 0) {
        $nAt = @($rnd | Where-Object { Test-RegraAtivaNoPerfil $_ $ativos }).Count
        if ($nAt -eq 0) { Add-Resultado 'Rede' 'Descoberta de rede (firewall)' 'ALERTA' ("nenhuma das {0} regras de entrada da Descoberta de Rede esta ativa no perfil atual ({1})" -f $rnd.Count, ($ativos -join ',')) 'Ative a Descoberta de Rede (Configuracoes avancadas de compartilhamento) ou rode com -HabilitarCompartilhamento' }
        else { Add-Resultado 'Rede' 'Descoberta de rede (firewall)' 'OK' ("{0} de {1} regras de entrada ativas" -f $nAt, $rnd.Count) }
    }
}
$sd = @()
foreach ($n in @('fdPHost', 'FDResPub')) {
    $x = Get-Service -Name $n -ErrorAction SilentlyContinue
    if ($x -and $x.Status -ne 'Running') { $sd += $n }
}
$script:ServDescoberta = $sd
if ($sd.Count -gt 0) { Add-Resultado 'Rede' 'Descoberta de rede (servicos)' 'ALERTA' ("parados: {0} (este PC nao aparece na rede / nomes nao resolvem por descoberta)" -f ($sd -join ', ')) 'Start-Service ou rode com -HabilitarCompartilhamento' }
else { Add-Resultado 'Rede' 'Descoberta de rede (servicos)' 'OK' 'fdPHost e FDResPub em execucao' }

# R.3 Adaptador, IP, gateway
try {
    $cfgs = @(Get-NetIPConfiguration -ErrorAction Stop | Where-Object { $_.NetAdapter.Status -eq 'Up' -and $_.IPv4Address })
    foreach ($c in $cfgs) {
        $ip4 = @($c.IPv4Address)[0].IPAddress
        $gw = if ($c.IPv4DefaultGateway) { @($c.IPv4DefaultGateway)[0].NextHop } else { 'nenhum' }
        if ($ip4 -like '169.254.*') {
            Add-Resultado 'Rede' ("Adaptador {0}" -f $c.InterfaceAlias) 'ALERTA' ("IP APIPA {0}: sem resposta de DHCP, o PC esta isolado" -f $ip4) 'Verifique cabo/Wi-Fi/roteador (DHCP) ou defina IP fixo'
        }
        else { Add-Resultado 'Rede' ("Adaptador {0}" -f $c.InterfaceAlias) 'INFO' ("IP {0}  gateway {1}" -f $ip4, $gw) }
    }
    if ($cfgs.Count -gt 1) { Add-Resultado 'Rede' 'Varios adaptadores ativos' 'INFO' 'Wi-Fi + cabo/VPN/virtual ao mesmo tempo: o Windows pode sair pelo adaptador/rede errada' }
    if ($cfgs.Count -eq 0) { Add-Resultado 'Rede' 'Adaptador de rede' 'ALERTA' 'nenhum adaptador com IPv4 ativo' 'Conecte-se a uma rede' }
}
catch { }

# R.4 Rota ate o destino
if ($Servidor -and -not $servidorLocal) {
    $ipDestino = $null
    if ($servidorEhIP) { $ipDestino = $Servidor }
    else { try { $ipDestino = ([System.Net.Dns]::GetHostAddresses($Servidor) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1).IPAddressToString } catch { } }

    try {
        $h = @(Select-String -Path (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') -Pattern ('^\s*[^#\s]+\s+.*\b{0}\b' -f [regex]::Escape($Servidor)) -ErrorAction Stop)
        if ($h.Count -gt 0) { Add-Resultado 'Rede' 'Arquivo hosts' 'ALERTA' ("entrada fixa para o destino: {0}" -f (($h | ForEach-Object { $_.Line.Trim() }) -join ' | ')) 'Confirme se o IP ainda e o atual; remova a linha se o servidor mudou de IP' }
    }
    catch { }

    if ($ipDestino) {
        $ping = $false
        try { $ping = Test-Connection -ComputerName $ipDestino -Count 1 -Quiet -ErrorAction Stop } catch { }
        Add-Resultado 'Rede' 'Ping ao destino' $(if ($ping) { 'OK' } else { 'INFO' }) ("{0}: {1}" -f $ipDestino, $(if ($ping) { 'responde' } else { 'sem resposta (ICMP pode estar bloqueado; o que vale e a porta 445)' }))

        try {
            $locais = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' })
            if ($locais.Count -gt 0) {
                $mesma = $false
                foreach ($l in $locais) { if (Test-MesmaSubrede $l.IPAddress $ipDestino $l.PrefixLength) { $mesma = $true } }
                if ($mesma) { Add-Resultado 'Rede' 'Sub-rede do destino' 'OK' ("{0} esta na mesma sub-rede deste PC" -f $ipDestino) }
                else { Add-Resultado 'Rede' 'Sub-rede do destino' 'INFO' ("{0} esta FORA das sub-redes locais ({1}): passa por roteador/VPN/VLAN; o firewall do destino costuma limitar o SMB a sub-rede local" -f $ipDestino, (($locais | ForEach-Object { "{0}/{1}" -f $_.IPAddress, $_.PrefixLength }) -join ', ')) }
            }
        }
        catch { }

        try {
            $viz = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.LinkLayerAddress -and $_.LinkLayerAddress -notmatch '^(00-00-00-00-00-00|FF-FF-FF-FF-FF-FF)$' -and $_.State.ToString() -notin 'Unreachable', 'Incomplete' })
            $dest = $viz | Where-Object { $_.IPAddress -eq $ipDestino } | Select-Object -First 1
            if ($dest) {
                $dup = @($viz | Where-Object { $_.LinkLayerAddress -eq $dest.LinkLayerAddress -and $_.IPAddress -ne $ipDestino })
                if ($dup.Count -gt 0) { Add-Resultado 'Rede' 'MAC duplicado (ARP)' 'ALERTA' ("o MAC {0} do destino tambem aparece para: {1}" -f $dest.LinkLayerAddress, (($dup | ForEach-Object { $_.IPAddress }) -join ', ')) 'MAC repetido em VM clonada, ou roteador com proxy-ARP. Gere novo MAC na VM ou confirme o IP do servidor' }
                else { Add-Resultado 'Rede' 'MAC do destino (ARP)' 'OK' ("{0} = {1}, sem duplicidade" -f $ipDestino, $dest.LinkLayerAddress) }
            }
        }
        catch { }
    }
}

# ----------------------------------------------------------------------------
Titulo 'BASICO DE REDE (o obvio: perfil, descoberta, firewall, adaptador, compartilhamento)'
# ----------------------------------------------------------------------------
$script:PerfisPublicos = @()
$script:PerfisAtivos = @()
$script:BindingsOff = @()
$aliasAtivos = @()
$gNet = '@FirewallAPI.dll,-32752'
$gFps = '@FirewallAPI.dll,-28502'

function Get-RegrasGrupo {
    param([string]$Grupo, [string]$Regex)
    $r = @(Get-NetFirewallRule -Group $Grupo -ErrorAction SilentlyContinue)
    if ($r.Count -eq 0) { $r = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayGroup -match $Regex }) }
    return $r
}

function Test-RegraAplica {
    param($Regra, $Cats)
    $p = [string]$Regra.Profile
    if ($p -match 'Any') { return $true }
    foreach ($c in $Cats) { if ($p -match $c) { return $true } }
    return $false
}

function Test-MesmaSubrede {
    param([string]$A, [string]$B, [int]$Prefixo)
    $ba = ([System.Net.IPAddress]::Parse($A)).GetAddressBytes()
    $bb = ([System.Net.IPAddress]::Parse($B)).GetAddressBytes()
    if ($ba.Length -ne 4 -or $bb.Length -ne 4) { return $false }
    $bits = $Prefixo
    for ($i = 0; $i -lt 4 -and $bits -gt 0; $i++) {
        $mask = if ($bits -ge 8) { 255 } else { (255 -shl (8 - $bits)) -band 255 }
        if (($ba[$i] -band $mask) -ne ($bb[$i] -band $mask)) { return $false }
        $bits -= 8
    }
    return $true
}

# B.1 Perfil da rede (Publica bloqueia descoberta e compartilhamento)
try {
    $perfis = @(Get-NetConnectionProfile -ErrorAction Stop)
    foreach ($pf in $perfis) {
        $cat = [string]$pf.NetworkCategory
        $script:PerfisAtivos += $cat
        $aliasAtivos += $pf.InterfaceAlias
        $txt = "'{0}' (interface {1}): {2}, IPv4={3}" -f $pf.Name, $pf.InterfaceAlias, $cat, $pf.IPv4Connectivity
        if ($cat -eq 'Public') {
            $script:PerfisPublicos += $pf
            Add-Resultado 'Basico' 'Perfil de rede' 'ALERTA' $txt 'Rede PUBLICA bloqueia descoberta e compartilhamento. Em rede confiavel: Set-NetConnectionProfile -InterfaceAlias <interface> -NetworkCategory Private (ou use -AjustarRede)'
        }
        else { Add-Resultado 'Basico' 'Perfil de rede' 'OK' $txt }
    }
    if ($perfis.Count -eq 0) { Add-Resultado 'Basico' 'Perfil de rede' 'ALERTA' 'nenhuma conexao de rede ativa encontrada' 'Conecte-se a uma rede (cabo/Wi-Fi)' }
}
catch { Add-Resultado 'Basico' 'Perfil de rede' 'INFO' ("nao foi possivel consultar: {0}" -f $_.Exception.Message) }

# B.2 Componentes ligados ao adaptador (Cliente p/ Redes Microsoft e Compartilhamento de Arquivos)
try {
    foreach ($ad in @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' -and ($aliasAtivos -contains $_.Name) })) {
        foreach ($cid in 'ms_msclient', 'ms_server') {
            $b = Get-NetAdapterBinding -Name $ad.Name -ComponentID $cid -ErrorAction SilentlyContinue
            if ($b -and -not $b.Enabled) {
                $script:BindingsOff += [pscustomobject]@{ Adaptador = $ad.Name; Id = $cid }
                Add-Resultado 'Basico' "Binding $cid em $($ad.Name)" 'FALHA' 'componente DESABILITADO no adaptador (Cliente para Redes Microsoft / Compartilhamento de Arquivos e Impressoras)' 'Enable-NetAdapterBinding -Name <adaptador> -ComponentID ms_msclient / ms_server (ou execute com -Corrigir)'
            }
        }
    }
    if ($script:BindingsOff.Count -eq 0 -and $aliasAtivos.Count -gt 0) { Add-Resultado 'Basico' 'Componentes do adaptador (ms_msclient / ms_server)' 'OK' 'habilitados nas conexoes ativas' }
}
catch { Add-Resultado 'Basico' 'Componentes do adaptador' 'INFO' ("nao foi possivel consultar: {0}" -f $_.Exception.Message) }

# B.3 Firewall: compartilhamento (SMB-In) e Descoberta de Rede para o perfil ativo
try {
    $mapaCat = @{ 'Private' = 'Private'; 'DomainAuthenticated' = 'Domain'; 'Public' = 'Public' }
    $catsNomes = @($script:PerfisAtivos | ForEach-Object { $mapaCat[$_] } | Where-Object { $_ } | Select-Object -Unique)
    if ($catsNomes.Count -gt 0) {
        $smbIn = Get-NetFirewallRule -Name 'FPS-SMB-In-TCP' -ErrorAction SilentlyContinue
        if ($smbIn) {
            $okSmb = ([string]$smbIn.Enabled -eq 'True') -and ([string]$smbIn.Action -eq 'Allow') -and (Test-RegraAplica $smbIn $catsNomes)
            if ($okSmb) { Add-Resultado 'Basico' 'Firewall: Compartilhamento de arquivos e impressoras (SMB-In)' 'OK' ("regra TCP 445 de entrada habilitada para o perfil {0}" -f ($catsNomes -join '/')) }
            else { Add-Resultado 'Basico' 'Firewall: Compartilhamento de arquivos e impressoras (SMB-In)' 'ALERTA' ("regra TCP 445 de entrada desabilitada ou nao aplicavel ao perfil {0}: outros PCs nao conseguem acessar este" -f ($catsNomes -join '/')) 'Em rede Privada: Enable-NetFirewallRule -Name FPS-SMB-In-TCP (ou -AjustarRede)' }
        }
        $descNet = @(Get-RegrasGrupo $gNet 'Network Discovery|Descoberta de Rede' | Where-Object { [string]$_.Direction -eq 'Inbound' -and (Test-RegraAplica $_ $catsNomes) })
        if ($descNet.Count -eq 0) { Add-Resultado 'Basico' 'Firewall: Descoberta de rede' 'INFO' 'nenhuma regra de entrada do grupo aplicavel ao perfil ativo' }
        else {
            $habN = @($descNet | Where-Object { [string]$_.Enabled -eq 'True' }).Count
            if ($habN -eq 0) { Add-Resultado 'Basico' 'Firewall: Descoberta de rede' 'ALERTA' ("DESATIVADA no perfil {0} (0 de {1} regras de entrada)" -f ($catsNomes -join '/'), $descNet.Count) 'Painel de Controle > Centro de Rede > Configuracoes de compartilhamento avancadas > Ativar descoberta de rede (ou -AjustarRede)' }
            else { Add-Resultado 'Basico' 'Firewall: Descoberta de rede' 'OK' ("{0} de {1} regras de entrada habilitadas" -f $habN, $descNet.Count) }
        }
        $descFps = @(Get-RegrasGrupo $gFps 'File and Printer Sharing|Compartilhamento de Arquivo' | Where-Object { [string]$_.Direction -eq 'Inbound' -and (Test-RegraAplica $_ $catsNomes) })
        if ($descFps.Count -gt 0) {
            $habF = @($descFps | Where-Object { [string]$_.Enabled -eq 'True' }).Count
            Add-Resultado 'Basico' 'Firewall: grupo Compartilhamento de arquivos e impressoras' 'INFO' ("{0} de {1} regras de entrada habilitadas" -f $habF, $descFps.Count)
        }
    }
    $fwOff = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { [string]$_.Enabled -eq 'False' })
    if ($fwOff.Count -gt 0) { Add-Resultado 'Basico' 'Firewall do Windows' 'INFO' ("desligado em: {0}. Antivirus/firewall de terceiros tambem podem bloquear 445." -f (($fwOff | ForEach-Object { $_.Name }) -join ', ')) }
}
catch { Add-Resultado 'Basico' 'Firewall' 'INFO' ("nao foi possivel consultar: {0}" -f $_.Exception.Message) }

# B.4 Servicos de descoberta (o PC so aparece em "Rede" se estiverem ativos)
foreach ($svc in 'fdPHost', 'FDResPub') {
    $sv = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($sv -and $sv.Status -ne 'Running') {
        $script:ServicosParados += $svc
        Add-Resultado 'Basico' "Servico $svc" 'ALERTA' 'parado: este PC nao aparece em "Rede" (descoberta). O acesso por nome/IP nao depende dele.' "Start-Service $svc (ou execute com -Corrigir)"
    }
    elseif ($sv) { Add-Resultado 'Basico' "Servico $svc" 'OK' 'em execucao' }
}

# B.5 Compartilhamentos existentes (papel de servidor)
if (-not $Servidor -or $servidorLocal) {
    try {
        $todosSh = @(Get-SmbShare -ErrorAction Stop)
        $usrSh = @($todosSh | Where-Object { -not $_.Special })
        if ($usrSh.Count -eq 0) { Add-Resultado 'Basico' 'Compartilhamentos neste PC' 'ALERTA' 'nenhum compartilhamento criado (alem dos administrativos)' 'New-SmbShare -Name Dados -Path C:\Dados -FullAccess <usuario>' }
        else { Add-Resultado 'Basico' 'Compartilhamentos neste PC' 'INFO' ((($usrSh | ForEach-Object { "{0} ({1})" -f $_.Name, $_.Path }) -join '; ')) }
        if ($Servidor -and $Compartilhamento -and (@($todosSh | ForEach-Object { $_.Name }) -notcontains $Compartilhamento)) {
            Add-Resultado 'Basico' "Compartilhamento '$Compartilhamento'" 'ALERTA' 'nao existe neste PC (daria erro 67, nao 86)' 'Confira o nome do compartilhamento'
        }
    }
    catch { }
}

# B.6 Alcance do servidor: mesma sub-rede, ping
if ($Servidor -and -not $servidorLocal) {
    try {
        $ips4 = @([System.Net.Dns]::GetHostAddresses($Servidor) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.IPAddressToString })
        $locais = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' })
        if ($ips4.Count -gt 0 -and $locais.Count -gt 0) {
            $mesma = $false
            foreach ($ipS in $ips4) { foreach ($l in $locais) { if (Test-MesmaSubrede $ipS $l.IPAddress ([int]$l.PrefixLength)) { $mesma = $true } } }
            if ($mesma) { Add-Resultado 'Basico' 'Mesma sub-rede do servidor' 'OK' ("{0} esta no mesmo segmento de rede" -f ($ips4 -join ', ')) }
            else { Add-Resultado 'Basico' 'Mesma sub-rede do servidor' 'INFO' ("{0} esta em OUTRA sub-rede (VLAN/VPN/Wi-Fi de convidados): a descoberta de rede nao atravessa. Use nome/IP." -f ($ips4 -join ', ')) }
        }
    }
    catch { }
    $ping = $false
    try { $ping = [bool](Test-Connection -ComputerName $Servidor -Count 1 -Quiet -ErrorAction Stop) } catch { }
    Add-Resultado 'Basico' 'Ping (ICMP)' 'INFO' $(if ($ping) { 'o servidor responde' } else { 'sem resposta (ICMP costuma ser bloqueado; o teste real e a porta TCP 445)' })
}

# B.7 MAC duplicado na rede (maquinas virtuais clonadas)
try {
    $meusMacs = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.MacAddress } | ForEach-Object { $_.MacAddress.ToUpper() })
    $meusIps = @(Get-NetIPAddress -ErrorAction SilentlyContinue | ForEach-Object { $_.IPAddress })
    $dupMac = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.LinkLayerAddress -and ($meusMacs -contains $_.LinkLayerAddress.ToUpper()) -and ($meusIps -notcontains $_.IPAddress) })
    if ($dupMac.Count -gt 0) { Add-Resultado 'Basico' 'MAC duplicado na rede' 'ALERTA' ("outro(s) IP(s) ({0}) usam o MESMO MAC deste PC: VM clonada ou adaptador duplicado" -f (($dupMac | ForEach-Object { $_.IPAddress } | Select-Object -Unique) -join ', ')) 'Gere novo MAC na VM/adaptador clonado' }
    else { Add-Resultado 'Basico' 'MAC duplicado na rede' 'OK' 'nenhum conflito na tabela ARP' }
}
catch { }

# ----------------------------------------------------------------------------
Titulo 'VETOR I - Credenciais, cofre, PIN, conta'
# ----------------------------------------------------------------------------
# I.1 Credential Manager
$cmd = @(& cmdkey /list 2>&1)
$alvosCofre = @($cmd | Where-Object { $_ -match '(?i)(Target|Destino|Alvo)\s*:' } | ForEach-Object { ($_ -replace '^\s*', '').Trim() })
if ($alvosCofre.Count -eq 0) {
    Add-Resultado 'I' 'Cofre de credenciais (cmdkey)' 'OK' 'nenhuma credencial salva'
}
else {
    $curto = if ($Servidor) { ($Servidor -split '\.')[0] } else { $null }
    $rel = @()
    if ($Servidor) { $rel = @($alvosCofre | Where-Object { $_ -match [regex]::Escape($Servidor) -or $_ -match [regex]::Escape($curto) }) }
    $script:CredRelacionadas = @($rel)
    if ($rel.Count -gt 0) {
        Add-Resultado 'I' 'Cofre de credenciais (cmdkey)' 'ALERTA' ("credencial salva para o servidor alvo (pode estar obsoleta): {0}" -f ($rel -join ' | ')) "cmdkey /delete:<alvo>   e depois   net use * /delete /y"
    }
    else {
        Add-Resultado 'I' 'Cofre de credenciais (cmdkey)' 'INFO' ("{0} credenciais salvas (nenhuma para o servidor alvo)" -f $alvosCofre.Count)
    }
}

# I.2 Conexoes existentes
$conn = @()
try { $conn = @(Get-SmbConnection -ErrorAction Stop) } catch { }
$map = @()
try { $map = @(Get-SmbMapping -ErrorAction Stop) } catch { }
if ($map.Count -gt 0) {
    $ruins = @($map | Where-Object { $_.Status -ne 'OK' })
    $script:MapsRuins = $ruins
    if ($ruins.Count -gt 0) {
        Add-Resultado 'I' 'Unidades mapeadas' 'ALERTA' ("{0} mapeamento(s) fora de OK: {1}" -f $ruins.Count, (($ruins | ForEach-Object { "$($_.LocalPath) $($_.RemotePath) [$($_.Status)]" }) -join '; ')) 'net use * /delete /y'
    }
    else { Add-Resultado 'I' 'Unidades mapeadas' 'INFO' ("{0} mapeamento(s) OK" -f $map.Count) }
}
if ($Servidor -and $conn.Count -gt 0) {
    $doSrv = @($conn | Where-Object { $_.ServerName -like "$Servidor*" -or $_.ServerName -like "$(($Servidor -split '\.')[0])*" })
    if ($doSrv.Count -gt 0) {
        $usrs = @($doSrv | Select-Object -ExpandProperty UserName -Unique)
        $sev = 'INFO'
        if ($Usuario -and ($usrs | Where-Object { $_ -ne $Usuario })) { $sev = 'ALERTA'; $script:SessaoConflito = $true }
        Add-Resultado 'I' 'Sessoes SMB ja abertas ao servidor' $sev ("usuario(s): {0}; dialeto(s): {1}" -f ($usrs -join ', '), ((($doSrv | Select-Object -ExpandProperty Dialect -Unique)) -join ', ')) 'Sessao anterior com outro usuario pode conflitar: net use \\servidor /delete'
    }
}

# I.3 Formato do usuario / caracteres nao-latinos
if ($uInfo) {
    if ($uInfo.Formato -eq 'simples') {
        Add-Resultado 'I' 'Formato do usuario' 'ALERTA' "'$Usuario' sem dominio/servidor" 'Use DOMINIO\usuario, SERVIDOR\usuario (conta local do servidor) ou usuario@dominio'
    }
    else { Add-Resultado 'I' 'Formato do usuario' 'OK' $uInfo.Formato }
}
# Autenticacao de passagem (pass-through): mesmo nome de usuario local no cliente e no servidor
if ($Servidor -and -not $servidorLocal) {
    $nomeTent = if ($uInfo) { $uInfo.Nome } else { $env:USERNAME }
    $semPrefixoSrv = (-not $uInfo) -or ($uInfo.Dominio -in @('', '.', $env:COMPUTERNAME))
    if ($nomeTent -ieq $env:USERNAME -and $semPrefixoSrv) {
        Add-Resultado 'I' 'Autenticacao de passagem (pass-through)' 'ALERTA' ("o usuario '{0}' existe AQUI e e o mesmo nome usado no servidor sem prefixo: o Windows envia o hash da senha LOCAL; se a senha do servidor for diferente, volta erro 86" -f $nomeTent) 'Use SERVIDOR\usuario com a senha do SERVIDOR (o teste ativo testa essa variante) ou sincronize as senhas'
    }
}
$nomesChecar = @($env:USERNAME, $env:COMPUTERNAME)
if ($Usuario) { $nomesChecar += $Usuario }
$naoLatino = @($nomesChecar | Where-Object { Test-NaoAscii $_ })
if ($naoLatino.Count -gt 0) {
    Add-Resultado 'I' 'Caracteres nao-ASCII em nomes' 'ALERTA' ("encontrado em: {0}" -f ($naoLatino -join ', ')) 'Use nomes de usuario/maquina somente com letras latinas e numeros (ver tambem Vetor VI)'
}
else { Add-Resultado 'I' 'Caracteres nao-ASCII em nomes' 'OK' 'nenhum' }

# I.3b Autenticacao de passagem (pass-through): mesmo nome de usuario nos dois PCs
if ($Servidor -and -not $servidorLocal) {
    $nomeAlvo = if ($uInfo) { $uInfo.Nome } else { $env:USERNAME }
    if ($nomeAlvo -ieq $env:USERNAME) {
        Add-Resultado 'I' 'Autenticacao de passagem (pass-through)' 'ALERTA' ("voce esta logado aqui como '{0}'. Se o destino tiver um usuario com o MESMO nome e senha diferente, conectar SEM credencial explicita envia o hash da senha local daqui e o servidor rejeita => 86" -f $nomeAlvo) 'Conecte com credencial explicita: net use \\SERVIDOR\compartilhamento /user:SERVIDOR\usuario *   (ou deixe as senhas iguais nos dois PCs)'
    }
    else { Add-Resultado 'I' 'Autenticacao de passagem (pass-through)' 'OK' ("usuario '{0}' difere do usuario logado ('{1}')" -f $nomeAlvo, $env:USERNAME) }
}

# I.4 Windows Hello / PIN
$ngc = Get-Dsreg 'NgcSet'
if ($ngc -eq 'YES') {
    Add-Resultado 'I' 'Windows Hello (PIN/biometria)' 'INFO' 'PIN configurado neste PC. Ao mapear unidade use a SENHA real da conta, nunca o PIN.'
}
elseif ($ngc) { Add-Resultado 'I' 'Windows Hello (PIN/biometria)' 'OK' 'nao configurado' }

# I.5 Politicas locais que interferem
$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$lbp = Get-RegValor $lsa 'LimitBlankPasswordUse'
if ($lbp -eq 0) { Add-Resultado 'I' 'LimitBlankPasswordUse' 'INFO' '0 = logon de rede com senha em branco PERMITIDO (inseguro)' }
else { Add-Resultado 'I' 'LimitBlankPasswordUse' 'INFO' 'padrao (1): contas sem senha NAO fazem logon de rede' }
$ddc = Get-RegValor $lsa 'DisableDomainCreds'
if ($ddc -eq 1) { Add-Resultado 'I' 'DisableDomainCreds' 'ALERTA' 'politica impede salvar credenciais de rede (checkbox "lembrar" nao funciona)' 'secpol.msc > Network access: Do not allow storage of passwords and credentials' }
$fg = Get-RegValor $lsa 'forceguest'
if ($fg -eq 1 -and -not $emDominio) {
    Add-Resultado 'I' 'Modelo de compartilhamento local (forceguest)' 'ALERTA' 'modo "Somente convidado": logons de rede com contas locais viram Guest' 'secpol.msc > Network access: Sharing and security model for local accounts = Classic'
}
else { Add-Resultado 'I' 'Modelo de compartilhamento local (forceguest)' 'OK' 'classico/dominio' }

# I.5b Contas locais habilitadas sem senha (logon de rede delas e bloqueado -> 0xC000006E)
try {
    $semSenha = @(Get-LocalUser -ErrorAction Stop | Where-Object { $_.Enabled -and ($_.PasswordRequired -eq $false -or $null -eq $_.PasswordLastSet) })
    if ($semSenha.Count -gt 0) {
        Add-Resultado 'I' 'Contas locais habilitadas sem senha' 'ALERTA' ("{0} (sem senha definida ou com troca pendente)" -f (($semSenha | ForEach-Object { $_.Name }) -join ', ')) 'Defina senha real (net user <conta> *) ou desabilite a conta; quem acessar com ela por rede recebe falha 0xC000006E'
    }
    else { Add-Resultado 'I' 'Contas locais habilitadas sem senha' 'OK' 'todas as contas habilitadas tem senha' }
}
catch { }

# I.6 Estado da conta informada
if ($uInfo) {
    $dom = $uInfo.Dominio
    $ehLocalAqui = ($dom -eq '' -or $dom -eq '.' -or $dom -ieq $env:COMPUTERNAME)
    if ($ehLocalAqui) {
        $info = Get-InfoUsuarioLocal $uInfo.Nome
        $script:InfoContaLocal = $info
        if ($info.Existe) { Write-ResultadoUsuarioLocal $info 'esta maquina' }
        elseif ($Servidor) { Add-Resultado 'I' "Conta '$($uInfo.Nome)' nesta maquina" 'INFO' 'nao existe aqui (se for conta local do SERVIDOR, use -TentarRemoto para checar la)' }
        else { Write-ResultadoUsuarioLocal $info 'esta maquina' }
    }
    elseif ($emDominio) {
        $ad = Get-InfoUsuarioAD $uInfo.Nome
        if ($null -eq $ad) { Add-Resultado 'I' "Conta AD '$($uInfo.Nome)'" 'ALERTA' 'nao encontrada no AD (ou sem acesso ao LDAP)' 'Confira o sAMAccountName e o dominio' }
        else {
            $p = $false
            if ($ad.Desabilitada) { $p = $true; Add-Resultado 'I' "Conta AD '$($uInfo.Nome)'" 'FALHA' 'conta DESABILITADA no AD' 'Habilitar no ADUC' }
            if ($ad.Bloqueada) { $p = $true; Add-Resultado 'I' "Conta AD '$($uInfo.Nome)'" 'FALHA' 'conta BLOQUEADA (lockout)' 'Unlock-ADAccount -Identity <usuario>' }
            if ($ad.SenhaExpirada) { $p = $true; Add-Resultado 'I' "Conta AD '$($uInfo.Nome)'" 'FALHA' 'SENHA EXPIRADA' 'Redefinir/alterar a senha' }
            if ($ad.TrocarNoLogon) { $p = $true; Add-Resultado 'I' "Conta AD '$($uInfo.Nome)'" 'FALHA' 'exige troca de senha no proximo logon' 'Faca logon interativo para trocar a senha' }
            if ($ad.ContaExpiraEm -and $ad.ContaExpiraEm -lt (Get-Date).ToUniversalTime()) { $p = $true; Add-Resultado 'I' "Conta AD '$($uInfo.Nome)'" 'FALHA' "conta EXPIROU em $($ad.ContaExpiraEm) UTC" 'Estender a validade da conta' }
            if (-not $p) { Add-Resultado 'I' "Conta AD '$($uInfo.Nome)'" 'OK' ("habilitada, sem bloqueio/expiracao. UPN: {0}" -f $ad.UPN) }
            else { Add-Resultado 'I' "UPN da conta" 'INFO' $ad.UPN }
        }
    }
    else {
        Add-Resultado 'I' "Estado da conta '$Usuario'" 'INFO' 'conta de outro dominio/maquina: nao verificavel daqui'
    }
}

# ----------------------------------------------------------------------------
Titulo 'VETOR II - NTLM / LAN Manager (LmCompatibilityLevel)'
# ----------------------------------------------------------------------------
$lm = Get-RegValor $lsa 'LmCompatibilityLevel'
$lmEfetivo = if ($null -eq $lm) { 3 } else { [int]$lm }
$lmTxt = @{
    0 = 'Envia LM e NTLM'; 1 = 'Envia LM e NTLM (NTLMv2 se negociado)'; 2 = 'Envia somente NTLM'
    3 = 'Envia somente NTLMv2 (padrao)'; 4 = 'Somente NTLMv2; DC recusa LM'; 5 = 'Somente NTLMv2; DC recusa LM e NTLM'
}
if ($lmEfetivo -lt 3) {
    Add-Resultado 'II' 'LmCompatibilityLevel (esta maquina)' 'FALHA' ("{0}{1} - {2}" -f $lmEfetivo, $(if ($null -eq $lm) { ' (nao definido)' } else { '' }), $lmTxt[$lmEfetivo]) 'Falha contra servidores/DCs nivel 4-5. Ajuste para 3: secpol.msc > Network security: LAN Manager authentication level > Send NTLMv2 response only'
}
elseif ($lmEfetivo -ge 4) {
    Add-Resultado 'II' 'LmCompatibilityLevel (esta maquina)' 'INFO' ("{0} - {1}. Parceiros antigos (NAS, Samba antigo, XP) que enviam NTLMv1 serao recusados." -f $lmEfetivo, $lmTxt[$lmEfetivo])
}
else {
    Add-Resultado 'II' 'LmCompatibilityLevel (esta maquina)' 'OK' ("{0} - {1}" -f $lmEfetivo, $lmTxt[$lmEfetivo])
}

$msv = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
$rs = Get-RegValor $msv 'RestrictSendingNTLMTraffic'
$rr = Get-RegValor $msv 'RestrictReceivingNTLMTraffic'
if ($rs -eq 2) { Add-Resultado 'II' 'RestrictSendingNTLMTraffic' 'ALERTA' '2 = envio de NTLM BLOQUEADO. Se Kerberos falhar (IP, SPN, horario) o fallback NTLM e negado e aparece 86' 'Use FQDN e corrija Kerberos, ou ajuste a GPO "Restrict NTLM: Outgoing NTLM traffic"' }
elseif ($rs -eq 1) { Add-Resultado 'II' 'RestrictSendingNTLMTraffic' 'INFO' '1 = auditar envio de NTLM' }
if ($rr -eq 2) { Add-Resultado 'II' 'RestrictReceivingNTLMTraffic' 'ALERTA' '2 = recebimento de NTLM BLOQUEADO nesta maquina (clientes por IP/workgroup falham)' 'GPO "Restrict NTLM: Incoming NTLM traffic"' }
if ($rs -ne 2 -and $rr -ne 2) { Add-Resultado 'II' 'Bloqueio de NTLM (MSV1_0)' 'OK' 'sem bloqueio de NTLM por politica' }
$minC = Get-RegValor $msv 'NtlmMinClientSec'
$minS = Get-RegValor $msv 'NtlmMinServerSec'
if ($null -ne $minC -or $null -ne $minS) {
    Add-Resultado 'II' 'NtlmMinClientSec / NtlmMinServerSec' 'INFO' ("cliente=0x{0:X} servidor=0x{1:X} (0x20080000 = exige NTLMv2 + 128 bits)" -f [int64]$minC, [int64]$minS)
}
$nolm = Get-RegValor $lsa 'NoLMHash'
if ($null -ne $nolm) { Add-Resultado 'II' 'NoLMHash' 'INFO' "$nolm (1 = hash LM nao armazenado)" }
try {
    $evNtlm = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-NTLM/Operational'; Id = 4001, 4002, 4003, 4004, 4005, 4006, 8001, 8002, 8003, 8004, 8005, 8006; StartTime = (Get-Date).AddHours(-$HorasEventos) } -MaxEvents 500 -ErrorAction Stop)
    if ($evNtlm.Count -gt 0) {
        $porId = ($evNtlm | Group-Object Id | Sort-Object Name | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count }) -join ', '
        Add-Resultado 'II' "Eventos NTLM/Operational (${HorasEventos}h)" 'ALERTA' ("{0} evento(s) de auditoria/bloqueio de NTLM (IDs: {1})" -f $evNtlm.Count, $porId) 'Abra Visualizador de Eventos > Microsoft-Windows-NTLM/Operational para ver quem usou/foi bloqueado'
    }
    else { Add-Resultado 'II' "Eventos NTLM/Operational (${HorasEventos}h)" 'OK' 'nenhum evento de auditoria/bloqueio de NTLM' }
}
catch { Add-Resultado 'II' 'Eventos NTLM/Operational' 'OK' 'sem eventos (ou auditoria de NTLM nao habilitada)' }
try {
    $nev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-NTLM/Operational'; StartTime = $ini } -ErrorAction Stop | Where-Object { $_.Id -ge 8001 -and $_.Id -le 8006 })
    if ($nev.Count -gt 0) {
        $idsN = ($nev | Group-Object Id | Sort-Object Name | ForEach-Object { "{0}x{1}" -f $_.Name, $_.Count }) -join ', '
        Add-Resultado 'II' "Eventos NTLM Operational (${HorasEventos}h)" 'ALERTA' ("{0} evento(s) de uso/bloqueio de NTLM (IDs: {1})" -f $nev.Count, $idsN) 'Veja Visualizador de Eventos > Microsoft-Windows-NTLM/Operational; se for bloqueio, use Kerberos (FQDN) ou ajuste a GPO de restricao de NTLM'
    }
    else { Add-Resultado 'II' "Eventos NTLM Operational (${HorasEventos}h)" 'OK' 'nenhum evento 8001-8006' }
}
catch { Add-Resultado 'II' "Eventos NTLM Operational (${HorasEventos}h)" 'INFO' 'sem eventos/log vazio (auditoria de NTLM provavelmente desligada)' }

# ----------------------------------------------------------------------------
Titulo 'VETOR III - UAC remoto / filtro de token'
# ----------------------------------------------------------------------------
$polSys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$latfp = Get-RegValor $polSys 'LocalAccountTokenFilterPolicy'
$fat = Get-RegValor $polSys 'FilterAdministratorToken'
$lua = Get-RegValor $polSys 'EnableLUA'
$latfpTxt = if ($null -eq $latfp) { 'nao definido (=0)' } else { "$latfp" }
if ($latfp -eq 1) {
    Add-Resultado 'III' 'LocalAccountTokenFilterPolicy (esta maquina)' 'OK' '1 - token de admin local nao e filtrado na rede'
}
else {
    $sev = if ($compAdmin) { 'ALERTA' } else { 'INFO' }
    Add-Resultado 'III' 'LocalAccountTokenFilterPolicy (esta maquina)' $sev ("{0} - admins LOCAIS (exceto o Administrador interno RID 500) recebem token filtrado em C$/ADMIN$ via rede{1}" -f $latfpTxt, $(if ($compAdmin) { ' [voce esta testando um compartilhamento administrativo]' } else { '' })) 'Se for acessar C$/ADMIN$ com conta local: New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWord -Force  (no SERVIDOR) ou use o Administrador interno'
}
if ($fat -eq 1) { Add-Resultado 'III' 'FilterAdministratorToken' 'ALERTA' '1 - ate o Administrador interno (RID 500) tem token filtrado (Admin Approval Mode)' 'Desative a politica "User Account Control: Admin Approval Mode for the Built-in Administrator account" ou use outra conta' }
if ($lua -eq 0) { Add-Resultado 'III' 'EnableLUA (UAC)' 'INFO' 'UAC desabilitado' }
$dlc = Get-RegValor $lsa 'DisableLoopbackCheck'
$bch = Get-RegValor $msv 'BackConnectionHostNames'
if ($Servidor -and $servidorLocal -and ($Servidor -ine $env:COMPUTERNAME) -and ($Servidor -notin @('localhost', '.'))) {
    if ($dlc -eq 1 -or $bch) { Add-Resultado 'III' 'Protecao de loopback' 'INFO' 'excecao configurada (DisableLoopbackCheck/BackConnectionHostNames)' }
    else { Add-Resultado 'III' 'Protecao de loopback' 'ALERTA' ("'{0}' e este mesmo PC acessado por IP/alias: a protecao de loopback do NTLM recusa a autenticacao" -f $Servidor) 'Acesse pelo nome do computador, ou adicione o alias em BackConnectionHostNames (preferivel a DisableLoopbackCheck=1)' }
}
elseif ($dlc -eq 1) { Add-Resultado 'III' 'DisableLoopbackCheck' 'INFO' '1 = protecao de loopback desativada (reduz a seguranca)' }
if ($uInfo -and ($uInfo.Dominio -eq '' -or $uInfo.Dominio -eq '.' -or $uInfo.Dominio -ieq $env:COMPUTERNAME) -and (Test-AdminLocalNaoRid500 $uInfo.Nome)) {
    Add-Resultado 'III' "Usuario '$($uInfo.Nome)'" 'ALERTA' 'e administrador local que NAO e o RID 500: sujeito ao filtro de token remoto' 'Veja LocalAccountTokenFilterPolicy acima (no servidor de destino)'
}
# Protecao de loopback: acessar ESTA maquina por um nome/alias diferente do proprio
if ($Servidor -and -not $servidorEhIP -and -not $servidorLocal) {
    try {
        $ipsSrvL = @([System.Net.Dns]::GetHostAddresses($Servidor) | ForEach-Object { $_.IPAddressToString })
        $ipsLocaisL = @(Get-NetIPAddress -ErrorAction SilentlyContinue | ForEach-Object { $_.IPAddress })
        if (@($ipsSrvL | Where-Object { $ipsLocaisL -contains $_ }).Count -gt 0) {
            $dlc = Get-RegValor $lsa 'DisableLoopbackCheck'
            $bch = Get-RegValor $msv 'BackConnectionHostNames'
            if ($dlc -eq 1 -or $bch) { Add-Resultado 'III' 'Protecao de loopback' 'INFO' 'excecao configurada (DisableLoopbackCheck/BackConnectionHostNames)' }
            else { Add-Resultado 'III' 'Protecao de loopback' 'ALERTA' "'$Servidor' aponta para ESTA maquina com um nome diferente do proprio: a protecao de loopback rejeita a autenticacao" 'Acesse pelo nome real do PC ou configure BackConnectionHostNames (preferivel a DisableLoopbackCheck)' }
        }
    }
    catch { }
}

# ----------------------------------------------------------------------------
Titulo 'VETOR IV - Transporte, DNS, porta 445, Azure'
# ----------------------------------------------------------------------------
if ($Servidor) {
    if ($servidorEhIP) {
        Add-Resultado 'IV' 'Destino por IP' 'ALERTA' 'acesso por IP NAO usa Kerberos (sem SPN): cai em NTLM, sujeito a LmCompatibilityLevel/bloqueio NTLM' 'Acesse pelo nome (FQDN) sempre que possivel'
    }
    else {
        try {
            $ips = @([System.Net.Dns]::GetHostAddresses($Servidor) | ForEach-Object { $_.IPAddressToString })
            Add-Resultado 'IV' 'Resolucao DNS' 'OK' ("{0} -> {1}" -f $Servidor, ($ips -join ', '))
        }
        catch { $script:DnsFalhou = $true; Add-Resultado 'IV' 'Resolucao DNS' 'FALHA' "nao foi possivel resolver '$Servidor' (evento SMBClient 30800)" 'Corrija DNS/hosts ou use o IP' }
    }
    if (Test-Porta $Servidor 445) { Add-Resultado 'IV' 'TCP 445' 'OK' 'porta alcancavel' }
    else { Add-Resultado 'IV' 'TCP 445' 'FALHA' 'porta 445 inacessivel (firewall/ISP). Em SMB 3.x isso pode aparecer como 86 em vez de timeout' 'Libere a 445 no firewall/VPN. Para Azure sobre internet, use VPN, ExpressRoute ou SMB over QUIC' }

    if ($Servidor -like '*.file.core.windows.net') {
        Add-Resultado 'IV' 'Destino Azure File Share' 'INFO' 'Teste de isolamento: mapeie com a Access Key: net use Z: \\conta.file.core.windows.net\share /user:Azure\<conta> <chave>. Se funcionar, o problema e identidade (UPN/sync/PRT), nao rede.'
        foreach ($k in @('AzureAdJoined', 'DomainJoined', 'AzureAdPrt', 'EnterpriseJoined')) {
            $v = Get-Dsreg $k
            if ($v) {
                $sev = 'INFO'
                if ($k -eq 'AzureAdPrt' -and $v -eq 'NO' -and ((Get-Dsreg 'AzureAdJoined') -eq 'YES')) { $sev = 'ALERTA' }
                Add-Resultado 'IV' "dsregcmd: $k" $sev $v $(if ($sev -eq 'ALERTA') { 'Sem PRT: dsregcmd /leave, reiniciar e dsregcmd /join (conforme relatorio)' } else { '' })
            }
        }
        if ($uInfo -and $uInfo.Formato -eq 'UPN') {
            Add-Resultado 'IV' 'Sufixo UPN' 'INFO' ("sufixo '{0}' precisa ser identico ao dominio verificado no Entra ID/Azure AD e sincronizado pelo Azure AD Connect" -f $uInfo.Dominio)
        }
    }
}
else {
    Add-Resultado 'IV' 'Transporte' 'INFO' 'informe -Servidor para testar DNS e porta 445'
}

$ini = (Get-Date).AddHours(-$HorasEventos)
try {
    $evc = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-SMBClient/Connectivity'; Id = 30800, 30803; StartTime = $ini } -ErrorAction Stop)
    if ($evc.Count -gt 0) {
        $e30800 = @($evc | Where-Object Id -eq 30800).Count
        $e30803 = @($evc | Where-Object Id -eq 30803).Count
        Add-Resultado 'IV' "Eventos SMBClient (ultimas ${HorasEventos}h)" 'ALERTA' ("30800 (falha de nome)={0}; 30803 (falha de conexao)={1}" -f $e30800, $e30803) 'Problema de transporte/nome, nao de senha. Resolva DNS/porta 445 primeiro.'
    }
}
catch { Add-Resultado 'IV' "Eventos SMBClient 30800/30803 (${HorasEventos}h)" 'OK' 'nenhum evento de falha de transporte' }

# ----------------------------------------------------------------------------
Titulo 'VETOR V - Canal seguro, SID, horario/Kerberos'
# ----------------------------------------------------------------------------
$sidMaquina = $null
try {
    $ua = Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop | Select-Object -First 1
    if ($ua) { $sidMaquina = ($ua.SID -replace '-\d+$', '') }
}
catch { }
if ($sidMaquina) { Add-Resultado 'V' 'SID da maquina' 'INFO' ("{0}  (compare com o do outro PC: se forem IGUAIS, e clone sem sysprep)" -f $sidMaquina) }
try {
    $e6167 = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 6167; StartTime = (Get-Date).AddDays(-7) } -MaxEvents 50 -ErrorAction Stop)
    if ($e6167.Count -gt 0) {
        Add-Resultado 'V' 'Evento 6167 (LsaSrv): ID de maquina divergente' 'FALHA' ("{0} ocorrencia(s) nos ultimos 7 dias, ultima em {1:dd/MM HH:mm}. Indica SID/ID de maquina duplicado (clone sem sysprep): o Windows 11 24H2/25H2 e o Server 2025 bloqueiam a autenticacao e o cliente ve erro 86." -f $e6167.Count, ($e6167 | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated) 'Gere novo SID (sysprep /generalize) ou reimplante a maquina clonada; confirme comparando o SID da maquina nos dois PCs'
    }
    else { Add-Resultado 'V' 'Evento 6167 (LsaSrv): ID de maquina divergente' 'OK' 'nenhum evento nos ultimos 7 dias' }
}
catch { Add-Resultado 'V' 'Evento 6167 (LsaSrv)' 'OK' 'nenhum evento nos ultimos 7 dias' }
try {
    $e6167 = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 6167; StartTime = $ini } -ErrorAction Stop)
    if ($e6167.Count -gt 0) {
        Add-Resultado 'V' "Evento 6167 LsaSrv (${HorasEventos}h)" 'FALHA' ("{0} ocorrencia(s), ultima {1:dd/MM HH:mm}: divergencia de Machine ID => SID duplicado/maquina clonada sem sysprep (bloqueio das atualizacoes KB5064081/KB5065426 no Win11 24H2/25H2 e Server 2025)" -f $e6167.Count, $e6167[0].TimeCreated) 'Reimplante a maquina clonada com sysprep /generalize (novo SID) ou use ferramenta de troca de SID; reentre no dominio se houver. Rode o script nos DOIS PCs e compare o SID.'
    }
    else { Add-Resultado 'V' "Evento 6167 LsaSrv (${HorasEventos}h)" 'OK' 'nenhum evento de Machine ID divergente' }
}
catch { Add-Resultado 'V' "Evento 6167 LsaSrv (${HorasEventos}h)" 'OK' 'nenhum evento de Machine ID divergente' }

if ($emDominio) {
    try {
        $ok = Test-ComputerSecureChannel -ErrorAction Stop
        $script:CanalOk = [bool]$ok
        if ($ok) { Add-Resultado 'V' 'Test-ComputerSecureChannel' 'OK' 'canal seguro com o dominio saudavel' }
        else { Add-Resultado 'V' 'Test-ComputerSecureChannel' 'FALHA' 'canal seguro QUEBRADO (relacao de confianca)' 'Test-ComputerSecureChannel -Repair -Credential (Get-Credential)  ou reingressar no dominio. Se clonada sem Sysprep, gere novo SID.' }
    }
    catch { Add-Resultado 'V' 'Test-ComputerSecureChannel' 'INFO' ("nao executado: {0}" -f $_.Exception.Message) }

    $nl = & nltest "/sc_verify:$($cs.Domain)" 2>&1 | Out-String
    $nlExit = $LASTEXITCODE
    if ($nlExit -eq 0 -and $nl -notmatch '0x56') { Add-Resultado 'V' 'nltest /sc_verify' 'OK' 'verificacao do canal seguro concluida sem erro' }
    elseif ($nl -match '0x56|\b86\b') { Add-Resultado 'V' 'nltest /sc_verify' 'FALHA' 'Trust Verification Status = 86 (ERROR_INVALID_PASSWORD): senha da conta de maquina dessincronizada ou SID duplicado' 'Reset do canal seguro / reingressar no dominio; se for clone, sysprep /generalize' }
    else { Add-Resultado 'V' 'nltest /sc_verify' 'ALERTA' ("codigo de saida {0}: {1}" -f $nlExit, (($nl -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 2) -join ' / ')) }
}
else {
    Add-Resultado 'V' 'Canal seguro de dominio' 'INFO' 'maquina em workgroup: nao se aplica'
}

# Horario
$w = & w32tm /query /status 2>&1 | Out-String
if ($w -match '(?i)(0x80070426|service has not been started|nao foi iniciado)') {
    Add-Resultado 'V' 'Servico de horario (w32time)' 'ALERTA' 'nao esta em execucao' 'Start-Service w32time; w32tm /resync'
}
$alvoHora = $null
if ($Servidor -and -not $servidorLocal) { $alvoHora = $Servidor }
elseif ($emDominio -and $env:LOGONSERVER) { $alvoHora = ($env:LOGONSERVER -replace '\\', '') }
if ($alvoHora) {
    $desvio = Get-DesvioHorario $alvoHora
    if ($null -eq $desvio) { Add-Resultado 'V' "Desvio de horario vs $alvoHora" 'INFO' 'nao foi possivel medir (alvo sem w32time/UDP 123 bloqueado)' }
    else {
        $abs = [math]::Abs($desvio)
        if ($abs -gt 300) { Add-Resultado 'V' "Desvio de horario vs $alvoHora" 'FALHA' ("{0:N1}s (> 300s: Kerberos falha e o fallback NTLM pode ser negado => 86)" -f $desvio) 'w32tm /resync /force  e corrija a fonte de tempo (PDC emulator)' }
        elseif ($abs -gt 120) { Add-Resultado 'V' "Desvio de horario vs $alvoHora" 'ALERTA' ("{0:N1}s (proximo do limite de 300s)" -f $desvio) 'w32tm /resync' }
        else { Add-Resultado 'V' "Desvio de horario vs $alvoHora" 'OK' ("{0:N3}s" -f $desvio) }
    }
}

# Kerberos para o servidor
if ($emDominio -and $Servidor -and -not $servidorEhIP -and -not $servidorLocal) {
    $kl = & klist get "cifs/$Servidor" 2>&1 | Out-String
    if ($kl -match '(?i)Error calling API|Erro ao chamar') {
        Add-Resultado 'V' "Kerberos (ticket cifs/$Servidor)" 'ALERTA' 'nao foi possivel obter ticket: SPN ausente/duplicado, horario ou DNS. O cliente cai em NTLM.' 'setspn -Q cifs/<servidor> ; confira duplicatas com setspn -X'
    }
    else { Add-Resultado 'V' "Kerberos (ticket cifs/$Servidor)" 'OK' 'ticket obtido' }
}

# ----------------------------------------------------------------------------
Titulo 'VETOR VI - Credential Guard / VBS'
# ----------------------------------------------------------------------------
$cgAtivo = $false
try {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop
    $cgAtivo = (@($dg.SecurityServicesRunning) -contains 1)
    $vbs = switch ([int]$dg.VirtualizationBasedSecurityStatus) { 0 { 'desligado' } 1 { 'habilitado, nao em execucao' } 2 { 'em execucao' } default { 'desconhecido' } }
    Add-Resultado 'VI' 'VBS' 'INFO' $vbs
    if ($cgAtivo) {
        $combo = (-not $emDominio) -and ((Test-NaoAscii $env:USERNAME) -or (Test-NaoAscii $Usuario))
        if ($combo) { Add-Resultado 'VI' 'Credential Guard + workgroup + usuario nao-latino' 'FALHA' 'combinacao documentada como causa de 86 (nome do usuario e corrompido no SESSION_SETUP)' 'Use usuario com caracteres latinos, ingresse a maquina no AD, ou desative Credential Guard/virtualizacao temporariamente' }
        else { Add-Resultado 'VI' 'Credential Guard' 'INFO' 'ativo (sem a combinacao problematica detectada)' }
    }
    else { Add-Resultado 'VI' 'Credential Guard' 'OK' 'nao esta em execucao' }
}
catch { Add-Resultado 'VI' 'Credential Guard' 'INFO' 'nao foi possivel consultar Win32_DeviceGuard' }
$tpmOk = $null; $sbOk = $null
try { $tpm = Get-Tpm -ErrorAction Stop; $tpmOk = [bool]($tpm.TpmPresent -and $tpm.TpmReady) } catch { }
try { $sbOk = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { }
$tpmTxt = if ($null -eq $tpmOk) { 'nao foi possivel consultar' } elseif ($tpmOk) { 'presente e pronto' } else { 'ausente ou nao pronto' }
$sbTxt = if ($null -eq $sbOk) { 'nao foi possivel consultar (BIOS legado ou sem privilegio)' } elseif ($sbOk) { 'ativado' } else { 'DESATIVADO' }
if ($cgAtivo -and ($tpmOk -eq $false -or $sbOk -eq $false)) {
    Add-Resultado 'VI' 'TPM / Secure Boot' 'ALERTA' ("Credential Guard ativo, mas TPM: {0}; Secure Boot: {1}. Raiz de confianca inconsistente pode invalidar segredos do LSA" -f $tpmTxt, $sbTxt) 'Corrija TPM/Secure Boot na BIOS/UEFI ou desative o Credential Guard'
}
else { Add-Resultado 'VI' 'TPM / Secure Boot' 'INFO' ("TPM: {0}; Secure Boot: {1}" -f $tpmTxt, $sbTxt) }
$cfg = Get-RegValor $lsa 'LsaCfgFlags'
if ($null -ne $cfg) { Add-Resultado 'VI' 'LsaCfgFlags' 'INFO' "$cfg (0=desligado, 1=ligado com UEFI lock, 2=ligado sem lock)" }
$sbOk = $null
try { $sbOk = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { }
$tpmInfo = $null
try { $tpmInfo = Get-Tpm -ErrorAction Stop } catch { }
$sbTxt = if ($null -eq $sbOk) { 'nao verificavel (BIOS legado ou sem privilegio de Administrador)' } elseif ($sbOk) { 'ativado' } else { 'DESATIVADO' }
Add-Resultado 'VI' 'Secure Boot' 'INFO' $sbTxt
if ($tpmInfo) { Add-Resultado 'VI' 'TPM' 'INFO' ("presente={0} pronto={1}" -f $tpmInfo.TpmPresent, $tpmInfo.TpmReady) }
if ($cgAtivo -and (($sbOk -eq $false) -or ($tpmInfo -and -not $tpmInfo.TpmReady))) {
    Add-Resultado 'VI' 'Credential Guard x Secure Boot/TPM' 'ALERTA' 'Credential Guard ativo com Secure Boot desativado ou TPM nao pronto: a raiz de confianca pode estar comprometida' 'Verifique BIOS/UEFI (Secure Boot, TPM 2.0) e o estado do VBS'
}

# ----------------------------------------------------------------------------
Titulo 'CONFIGURACAO SMB (assinatura, criptografia, SMB1)'
# ----------------------------------------------------------------------------
$cli = $null
try { $cli = Get-SmbClientConfiguration -ErrorAction Stop } catch { }
if ($cli) {
    Add-Resultado 'SMB' 'Cliente: assinatura' $(if (-not $cli.EnableSecuritySignature -and -not $cli.RequireSecuritySignature) { 'ALERTA' } else { 'OK' }) ("Enable={0} Require={1}" -f $cli.EnableSecuritySignature, $cli.RequireSecuritySignature) 'Se o servidor exige assinatura, habilite: Set-SmbClientConfiguration -EnableSecuritySignature $true'
    Add-Resultado 'SMB' 'Cliente: logons de convidado inseguros' 'INFO' ("EnableInsecureGuestLogons={0}" -f $cli.EnableInsecureGuestLogons)
    if ([int]$os.BuildNumber -ge 26100 -and $cli.RequireSecuritySignature -and -not $cli.EnableInsecureGuestLogons) {
        Add-Resultado 'SMB' 'Windows 11 24H2+: assinatura obrigatoria e convidado' 'INFO' 'assinatura SMB exigida e convidado inseguro desabilitado: compartilhamentos SEM senha/convidado (NAS antigo, TV, Samba legado) falham com 86 (nao ha chave para assinar). Nao e alterado automaticamente: afrouxar isso reduz a seguranca.'
    }
    if ($cli.RequireSecuritySignature -and -not $cli.EnableInsecureGuestLogons) {
        Add-Resultado 'SMB' 'Assinatura exigida + convidado bloqueado' 'INFO' 'padrao do Windows 11 24H2+: sessao de convidado/sem senha nao consegue assinar, entao NAS, TVs e PCs com pasta publica sem senha falham com 86' 'Use um usuario/senha no destino. Se for dispositivo legado: -PermitirConvidadoInseguro e/ou -RelaxarAssinaturaCliente (reduzem a seguranca)'
    }
    $pgu = Get-RegValor 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' 'AllowInsecureGuestAuth'
    if ($null -ne $pgu) { Add-Resultado 'SMB' 'Politica AllowInsecureGuestAuth' 'INFO' ("definida por politica = {0} (sobrescreve a configuracao local)" -f $pgu) }
    if ($cli.PSObject.Properties.Name -contains 'BlockNTLM') {
        Add-Resultado 'SMB' 'Cliente: BlockNTLM' $(if ($cli.BlockNTLM) { 'ALERTA' } else { 'OK' }) ("BlockNTLM={0}" -f $cli.BlockNTLM) 'Com BlockNTLM, acesso por IP ou sem Kerberos falha (86). Use FQDN e corrija Kerberos.'
    }
}
$srv = $null
try { $srv = Get-SmbServerConfiguration -ErrorAction Stop } catch { }
if ($srv) {
    Add-Resultado 'SMB' 'Servidor (esta maquina): assinatura' 'INFO' ("Enable={0} Require={1}" -f $srv.EnableSecuritySignature, $srv.RequireSecuritySignature)
    Add-Resultado 'SMB' 'Servidor (esta maquina): criptografia' 'INFO' ("EncryptData={0} RejectUnencryptedAccess={1}" -f $srv.EncryptData, $srv.RejectUnencryptedAccess)
    Add-Resultado 'SMB' 'Servidor (esta maquina): protocolos' 'INFO' ("SMB1={0} SMB2/3={1}" -f $srv.EnableSMB1Protocol, $srv.EnableSMB2Protocol)
    if ($srv.PSObject.Properties.Name -contains 'InvalidAuthenticationDelayTimeInMs') {
        Add-Resultado 'SMB' 'Servidor: limitador de autenticacao (2025/11 24H2)' 'INFO' ("atraso apos falha = {0} ms (tentativas repetidas ficam lentas)" -f $srv.InvalidAuthenticationDelayTimeInMs)
    }
}
if ($Servidor -and $conn.Count -gt 0) {
    $c1 = $conn | Where-Object { $_.ServerName -like "$Servidor*" } | Select-Object -First 1
    if ($c1) { Add-Resultado 'SMB' 'Conexao atual ao servidor' 'INFO' ("dialeto {0}, usuario {1}, criptografada={2}" -f $c1.Dialect, $c1.UserName, $c1.Encrypted) }
}

# ----------------------------------------------------------------------------
Titulo ("EVENTOS DE SEGURANCA 4625 (ultimas ${HorasEventos}h, esta maquina)")
# ----------------------------------------------------------------------------
$mapaSub = @{
    '0xc000006a' = 'Senha incorreta (equivale ao 86)'
    '0xc000006d' = 'Usuario/senha invalidos (generico)'
    '0xc0000064' = 'Usuario nao existe'
    '0xc0000071' = 'Senha expirada'
    '0xc0000072' = 'Conta desabilitada'
    '0xc0000234' = 'Conta bloqueada'
    '0xc0000193' = 'Conta expirada'
    '0xc0000224' = 'Deve trocar senha no proximo logon'
    '0xc000006e' = 'Restricao de conta (inclui conta sem senha em rede)'
    '0xc000006f' = 'Fora do horario permitido'
    '0xc0000070' = 'Restricao de estacao de trabalho'
    '0xc000015b' = 'Tipo de logon nao concedido (direito "Acessar este computador pela rede")'
    '0xc0000133' = 'Relogios fora de sincronia'
    '0xc0000190' = 'Falha de relacao de confianca'
    '0xc000018b' = 'Conta de maquina inexistente no dominio'
}
if (-not $ehAdmin) {
    Add-Resultado '4625' 'Leitura do log Security' 'INFO' 'execute como Administrador para analisar falhas de logon'
}
else {
    try {
        $evs = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $ini } -MaxEvents 1000 -ErrorAction Stop)
        $lista = foreach ($e in $evs) {
            $x = [xml]$e.ToXml()
            $d = @{}
            foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
            [pscustomobject]@{
                Hora = $e.TimeCreated; Usuario = $d['TargetUserName']; Dominio = $d['TargetDomainName']
                Status = ([string]$d['Status']).ToLower(); Sub = ([string]$d['SubStatus']).ToLower(); Pacote = $d['AuthenticationPackageName']
                Tipo = $d['LogonType']; Origem = $d['IpAddress']; Estacao = $d['WorkstationName']
            }
        }
        if ($Usuario) { $lista = @($lista | Where-Object { $_.Usuario -ieq $uInfo.Nome }) }
        if (@($lista).Count -eq 0) {
            Add-Resultado '4625' 'Falhas de logon' 'OK' $(if ($Usuario) { "nenhuma falha para '$($uInfo.Nome)' no periodo" } else { 'nenhuma falha no periodo' })
        }
        else {
            $gr = @($lista | Group-Object Sub | Sort-Object Count -Descending)
            foreach ($g in $gr) {
                $desc = if ($mapaSub.ContainsKey($g.Name)) { $mapaSub[$g.Name] } elseif ($g.Name -eq '0x0') { 'SubStatus 0x0: o Windows nao detalhou o motivo (veja usuario/origem abaixo)' } else { 'SubStatus desconhecido' }
                Add-Resultado '4625' ("SubStatus {0}" -f $g.Name) 'ALERTA' ("{0} ocorrencia(s) - {1}" -f $g.Count, $desc)
            }
            Write-Host '         Ultimas falhas:' -ForegroundColor DarkGray
            $lista | Sort-Object Hora -Descending | Select-Object -First 5 | ForEach-Object {
                Write-Host ('           {0:HH:mm:ss} {1}\{2} pacote={3} tipo={4} origem={5} estacao={6}' -f $_.Hora, $_.Dominio, $_.Usuario, $_.Pacote, $_.Tipo, $_.Origem, $_.Estacao) -ForegroundColor DarkGray
            }
            $origens = @($lista | Group-Object { '{0}\{1} | ip={2} | estacao={3} | tipo={4} | pacote={5} | status={6}/{7}' -f $_.Dominio, $_.Usuario, $_.Origem, $_.Estacao, $_.Tipo, $_.Pacote, $_.Status, $_.Sub } | Sort-Object Count -Descending | Select-Object -First 10)
            foreach ($o in $origens) {
                $ult = ($o.Group | Sort-Object Hora -Descending | Select-Object -First 1).Hora
                Add-Resultado '4625' 'Origem das falhas' 'INFO' ('{0}x  {1}  (ultima: {2:dd/MM HH:mm:ss})' -f $o.Count, $o.Name, $ult)
            }
            $ntlm1 = @($lista | Where-Object { $_.Pacote -eq 'NTLM' }).Count
            if ($ntlm1 -gt 0) { Add-Resultado '4625' 'Falhas via pacote NTLM' 'INFO' "$ntlm1 falha(s) usando NTLM (indicio de fallback de Kerberos ou acesso por IP)" }
        }
    }
    catch {
        if ($_.Exception.Message -match '(?i)No events were found|Nenhum evento') { Add-Resultado '4625' 'Falhas de logon' 'OK' 'nenhuma falha no periodo' }
        else { Add-Resultado '4625' 'Leitura do log Security' 'INFO' $_.Exception.Message }
    }
}

# ----------------------------------------------------------------------------
if ($TentarRemoto -and $Servidor -and -not $servidorLocal) {
    Titulo ("COMPARACAO COM O SERVIDOR $Servidor (WinRM)")
    $fnTexto = ${function:Get-InfoUsuarioLocal}.ToString()
    $nomeLocalRemoto = $null
    if ($uInfo -and ($uInfo.Dominio -eq '' -or $uInfo.Dominio -eq '.' -or $uInfo.Dominio -ieq ($Servidor -split '\.')[0])) { $nomeLocalRemoto = $uInfo.Nome }
    $sb = {
        param($fn, $nomeUsr)
        $lsaK = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        $pol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        function V($p, $n) { try { (Get-ItemProperty -Path $p -Name $n -ErrorAction Stop).$n } catch { $null } }
        $sid = $null
        try { $u = Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' | Select-Object -First 1; if ($u) { $sid = ($u.SID -replace '-\d+$', '') } } catch { }
        $sc = $null; try { $sc = Get-SmbServerConfiguration } catch { }
        $csr = Get-CimInstance Win32_ComputerSystem
        $usr = $null
        if ($nomeUsr) { try { $usr = & ([scriptblock]::Create($fn)) $nomeUsr } catch { } }
        [pscustomobject]@{
            Lm = V $lsaK 'LmCompatibilityLevel'; ForceGuest = V $lsaK 'forceguest'
            RestrictRecv = V "$lsaK\MSV1_0" 'RestrictReceivingNTLMTraffic'
            Latfp = V $pol 'LocalAccountTokenFilterPolicy'; FilterAdm = V $pol 'FilterAdministratorToken'
            MachineSid = $sid; UtcAgora = (Get-Date).ToUniversalTime()
            EmDominio = [bool]$csr.PartOfDomain; Dominio = $csr.Domain
            RequerAssinatura = $(if ($sc) { $sc.RequireSecuritySignature } else { $null })
            Criptografa = $(if ($sc) { $sc.EncryptData } else { $null })
            SMB1 = $(if ($sc) { $sc.EnableSMB1Protocol } else { $null })
            Usuario = $usr
        }
    }
    try {
        $icp = @{ ComputerName = $Servidor; ScriptBlock = $sb; ArgumentList = @($fnTexto, $nomeLocalRemoto); ErrorAction = 'Stop' }
        if ($CredencialRemota) { $icp.Credential = $CredencialRemota }
        $r = Invoke-Command @icp

        $lmR = if ($null -eq $r.Lm) { 3 } else { [int]$r.Lm }
        if ($lmEfetivo -lt 3 -and $lmR -ge 4) { Add-Resultado 'II' 'LmCompatibilityLevel: cliente x servidor' 'FALHA' ("cliente={0} (envia NTLMv1) / servidor={1} (recusa NTLMv1)" -f $lmEfetivo, $lmR) 'Suba o CLIENTE para nivel 3' }
        else { Add-Resultado 'II' 'LmCompatibilityLevel: cliente x servidor' 'OK' ("cliente={0} / servidor={1}" -f $lmEfetivo, $lmR) }
        if ($r.RestrictRecv -eq 2) { Add-Resultado 'II' 'Servidor: bloqueio de NTLM de entrada' 'FALHA' 'RestrictReceivingNTLMTraffic=2 no servidor' 'Use Kerberos (FQDN no dominio) ou ajuste a GPO' }
        if ($r.ForceGuest -eq 1 -and -not $r.EmDominio) { Add-Resultado 'I' 'Servidor: forceguest' 'FALHA' 'servidor em modo "Somente convidado": contas locais viram Guest' 'secpol.msc > Network access: Sharing and security model = Classic' }
        if ($compAdmin -and $r.Latfp -ne 1) { Add-Resultado 'III' 'Servidor: LocalAccountTokenFilterPolicy' 'ALERTA' ("valor={0}" -f $(if ($null -eq $r.Latfp) { 'nao definido' } else { $r.Latfp })) 'Defina 1 no servidor ou use o Administrador interno' }
        if ($r.FilterAdm -eq 1) { Add-Resultado 'III' 'Servidor: FilterAdministratorToken' 'ALERTA' '1 - Administrador interno tambem e filtrado' }
        if ($sidMaquina -and $r.MachineSid -and $sidMaquina -eq $r.MachineSid) { Add-Resultado 'V' 'SID duplicado' 'FALHA' ("cliente e servidor com o mesmo SID de maquina: {0}" -f $sidMaquina) 'Reimplante uma das maquinas com Sysprep /generalize (novo SID)' }
        else { Add-Resultado 'V' 'SID cliente x servidor' 'OK' 'diferentes' }
        $dif = [math]::Abs(((Get-Date).ToUniversalTime() - $r.UtcAgora).TotalSeconds)
        if ($dif -gt 300) { Add-Resultado 'V' 'Horario cliente x servidor (via WinRM)' 'FALHA' ("{0:N0}s de diferenca" -f $dif) 'w32tm /resync nos dois lados' }
        else { Add-Resultado 'V' 'Horario cliente x servidor (via WinRM)' 'OK' ("{0:N1}s de diferenca" -f $dif) }
        if ($r.RequerAssinatura -and $cli -and -not $cli.EnableSecuritySignature) { Add-Resultado 'SMB' 'Assinatura: servidor exige, cliente nao suporta' 'FALHA' 'incompatibilidade de assinatura SMB' 'Set-SmbClientConfiguration -EnableSecuritySignature $true' }
        else { Add-Resultado 'SMB' 'Servidor: assinatura/criptografia/SMB1' 'INFO' ("RequireSigning={0} EncryptData={1} SMB1={2}" -f $r.RequerAssinatura, $r.Criptografa, $r.SMB1) }
        if ($r.Usuario) { Write-ResultadoUsuarioLocal $r.Usuario "servidor $Servidor" }
        elseif ($nomeLocalRemoto) { Add-Resultado 'I' "Conta '$nomeLocalRemoto' no servidor" 'INFO' 'nao foi possivel consultar' }
    }
    catch {
        Add-Resultado 'Remoto' 'WinRM' 'INFO' ("nao foi possivel consultar {0}: {1}" -f $Servidor, $_.Exception.Message)
    }
}

# ----------------------------------------------------------------------------
function Invoke-BlocoTesteAtivo {
    param([string]$Fase = '')
    if (-not $Servidor) { return }
    Titulo ('TESTE ATIVO DE AUTENTICACAO (codigo Win32 real)' + $Fase)
    if (-not ('Erro86Net' -as [type])) {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
public struct Erro86Res {
    public int dwScope; public int dwType; public int dwDisplayType; public int dwUsage;
    public string lpLocalName; public string lpRemoteName; public string lpComment; public string lpProvider;
}
public static class Erro86Net {
    [DllImport("mpr.dll", CharSet=CharSet.Unicode)]
    public static extern int WNetAddConnection2(ref Erro86Res r, string pw, string user, int flags);
    [DllImport("mpr.dll", CharSet=CharSet.Unicode)]
    public static extern int WNetCancelConnection2(string name, int flags, bool force);
}
"@
    }
    $codigos = @{
        0 = 'Sucesso - autenticacao OK'
        5 = 'Acesso negado (autenticou; faltam permissoes/UAC remoto)'
        53 = 'Caminho de rede nao encontrado (transporte)'
        67 = 'Nome do compartilhamento invalido'
        86 = 'ERRO 86 - senha de rede incorreta (rejeicao do hash/token)'
        1203 = 'Nenhum provedor de rede aceitou o caminho'
        1219 = 'Conexao previa com outras credenciais (net use * /delete)'
        1311 = 'Nenhum servidor de logon disponivel'
        1326 = 'Usuario ou senha incorretos'
        1330 = 'Senha expirada'
        1331 = 'Conta desabilitada'
        1355 = 'Dominio inexistente/inacessivel'
        1385 = 'Tipo de logon nao concedido'
        1396 = 'Nome de destino incorreto (Kerberos/SPN)'
        1786 = 'Relacao de confianca da estacao falhou'
        1788 = 'Relacao de confianca falhou'
        1907 = 'Deve trocar a senha no proximo logon'
        1909 = 'Conta bloqueada'
    }
    $caminho = '\\{0}\{1}' -f $Servidor, $Compartilhamento
    $netUseAntes = (& net use 2>&1 | Out-String)
    $jaExistia = $netUseAntes -match [regex]::Escape($caminho)

    function Invoke-TesteSmb {
        param([string]$Rotulo, [string]$Usr, [string]$Senha)
        $nr = New-Object Erro86Res
        $nr.dwType = 1
        $nr.lpRemoteName = $caminho
        $rc = [Erro86Net]::WNetAddConnection2([ref]$nr, $Senha, $Usr, 0)
        $desc = if ($codigos.ContainsKey($rc)) { $codigos[$rc] } else { 'codigo nao mapeado (net helpmsg ' + $rc + ')' }
        $sev = switch ($rc) { 0 { 'OK' } 86 { 'FALHA' } 5 { 'ALERTA' } 1219 { 'ALERTA' } default { 'FALHA' } }
        Add-Resultado 'Teste' $Rotulo $sev ("{0} -> codigo {1}: {2}" -f $caminho, $rc, $desc)
        if ($rc -eq 0 -and -not $jaExistia) { [void][Erro86Net]::WNetCancelConnection2($caminho, 0, $true) }
        return $rc
    }

    $rcs = @{}
    $rcs['contexto'] = Invoke-TesteSmb 'Contexto atual (token do usuario logado)' $null $null

    if ($Credencial) {
        $senha = $Credencial.GetNetworkCredential().Password
        $u0 = $Credencial.UserName
        $rcs['como'] = Invoke-TesteSmb ("Credencial como digitada ({0})" -f $u0) $u0 $senha
        if ($uInfo -and $uInfo.Formato -eq 'simples') {
            if (-not $servidorEhIP) { $rcs['srv'] = Invoke-TesteSmb ("Variante SERVIDOR\usuario") ("{0}\{1}" -f ($Servidor -split '\.')[0], $uInfo.Nome) $senha }
            $rcs['pt'] = Invoke-TesteSmb 'Variante .\usuario' (".\{0}" -f $uInfo.Nome) $senha
            if ($emDominio) { $rcs['dom'] = Invoke-TesteSmb ("Variante {0}\usuario" -f $cs.Domain) ("{0}\{1}" -f $cs.Domain, $uInfo.Nome) $senha }
        }
        $senha = $null
    }
    else {
        Add-Resultado 'Teste' 'Credencial explicita' 'INFO' 'para testar usuario/senha informe -Credencial (Get-Credential). A senha nunca e exibida nem gravada.'
    }

    if ($rcs.ContainsKey('contexto') -and $rcs['contexto'] -eq 86 -and $rcs.ContainsKey('como') -and $rcs['como'] -eq 0) {
        Add-Resultado 'Teste' 'Conclusao: autenticacao de passagem' 'FALHA' 'o contexto atual da erro 86, mas a credencial explicita funciona => causa: pass-through (mesmo nome de usuario, senha diferente). Conecte sempre com SERVIDOR\usuario e a senha do servidor.'
    }
    $variantesOk = @('srv', 'pt', 'dom') | Where-Object { $rcs.ContainsKey($_) -and $rcs[$_] -eq 0 }
    if ($rcs.ContainsKey('como') -and $rcs['como'] -ne 0 -and @($variantesOk).Count -gt 0) {
        Add-Resultado 'Teste' 'Conclusao: formato do usuario' 'FALHA' ("o usuario como digitado falhou, mas funciona em outra forma (teste: {0}) => use o formato completo SERVIDOR\usuario" -f (@($variantesOk) -join ','))
    }
    if ($rcs.Values -contains 86) {
        Add-Resultado 'Teste' 'Conclusao do teste ativo' 'FALHA' 'o ERRO 86 foi reproduzido. Cruze com os itens FALHA/ALERTA acima (conta, NTLM, horario, canal seguro, 445).'
    }
}

# ----------------------------------------------------------------------------
Invoke-BlocoTesteAtivo

# ----------------------------------------------------------------------------
# FASE DE CORRECAO (somente com -Corrigir / -Simular)
# ----------------------------------------------------------------------------
if ($Corrigir) {
    $script:Fase = 'pos'
    if ($Simular) { Titulo 'CORRECOES - SIMULACAO (nada sera alterado)' } else { Titulo 'CORRECOES AUTOMATICAS (apos a verificacao)' }

    # 1) LmCompatibilityLevel
    if ($lmEfetivo -lt 3) {
        Invoke-Correcao 'II' 'LmCompatibilityLevel (esta maquina)' ("{0} -> 3 (somente NTLMv2)" -f $lmEfetivo) {
            Set-RegDword $lsa 'LmCompatibilityLevel' 3
        } {
            [int](Get-RegValor $lsa 'LmCompatibilityLevel') -eq 3
        }
        if ($emDominio) { Add-Correcao 'II' 'Aviso GPO' 'MANUAL' 'maquina em dominio: se uma GPO definir esse nivel, ela sobrescreve a correcao no proximo gpupdate. Corrija na GPO.' }
    }

    # 2) Servicos parados
    foreach ($svc in $script:ServicosParados) {
        Invoke-Correcao 'Contexto' "Servico $svc" 'inicializacao Automatica + iniciar servico' {
            Backup-Servico $svc
            Set-Service -Name $svc -StartupType Automatic -ErrorAction Stop
            Start-Service -Name $svc -ErrorAction Stop
        } {
            (Get-Service -Name $svc).Status -eq 'Running'
        }
    }

    # 3) Horario (Kerberos / fallback NTLM)
    if ($script:ServicosParados -contains 'w32time') {
        Invoke-Correcao 'V' 'Servico de horario (w32time)' 'ressincronizar o relogio (w32tm /resync /force)' {
            $o = & w32tm /resync /force 2>&1 | Out-String
            if ($LASTEXITCODE -ne 0 -and -not $emDominio) {
                Backup-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' 'NtpServer'
                Backup-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' 'Type'
                $peers = (($ServidoresNtp -split '[,; ]+' | Where-Object { $_ }) | ForEach-Object { "$_,0x8" }) -join ' '
                & w32tm /config "/manualpeerlist:$peers" /syncfromflags:manual /reliable:no /update | Out-Null
                Start-Sleep -Seconds 2
                $o = & w32tm /resync /force 2>&1 | Out-String
            }
            if ($LASTEXITCODE -ne 0) { throw ("w32tm /resync falhou: " + $o.Trim()) }
        } { $true }
    }

    # 4) Assinatura SMB do cliente
    if ($cli -and -not $cli.EnableSecuritySignature -and -not $cli.RequireSecuritySignature) {
        Invoke-Correcao 'SMB' 'Cliente: assinatura' 'habilitar EnableSecuritySignature' {
            $script:Backup.Add([pscustomobject]@{ Tipo = 'SmbClientSign'; Valor = $false }); Save-Backup
            Set-SmbClientConfiguration -EnableSecuritySignature $true -Force -Confirm:$false
        } {
            [bool](Get-SmbClientConfiguration).EnableSecuritySignature
        }
    }

    # 5) forceguest em workgroup
    if ($fg -eq 1 -and -not $emDominio) {
        Invoke-Correcao 'I' 'Modelo de compartilhamento local (forceguest)' 'forceguest 1 -> 0 (modelo classico)' {
            Set-RegDword $lsa 'forceguest' 0
        } {
            [int](Get-RegValor $lsa 'forceguest') -eq 0
        }
    }

    # 6) Credenciais salvas do servidor alvo, sessoes conflitantes, mapeamentos quebrados
    if ($Servidor) {
        foreach ($linha in $script:CredRelacionadas) {
            $alvoCred = $null
            if ($linha -match 'target=(?<t>.+)$') { $alvoCred = $Matches.t.Trim() }
            if ($alvoCred) {
                Invoke-Correcao 'I' 'Cofre de credenciais (cmdkey)' ("remover credencial salva '{0}' (nao restauravel pelo backup)" -f $alvoCred) {
                    & cmdkey /delete:$alvoCred | Out-Null
                } {
                    @(@(& cmdkey /list) | Select-String -SimpleMatch "target=$alvoCred").Count -eq 0
                }
            }
        }
        if ($script:SessaoConflito) {
            $curtoNome = ($Servidor -split '\.')[0]
            $remotos = @()
            foreach ($l in @(& net use 2>&1 | ForEach-Object { [string]$_ })) {
                if ($l -match '(\\\\[^\s\\]+\\[^\s]+)') {
                    $rem = $Matches[1]
                    if ($rem -like "\\$Servidor\*" -or $rem -like "\\$curtoNome\*") { $remotos += $rem }
                }
            }
            foreach ($rem in ($remotos | Select-Object -Unique)) {
                Invoke-Correcao 'I' 'Sessoes SMB ja abertas ao servidor' ("encerrar conexao {0} (usuario diferente do informado)" -f $rem) {
                    & net use $rem /delete /y | Out-Null
                } { $true }
            }
        }
    }
    foreach ($m in $script:MapsRuins) {
        if ($m.LocalPath) {
            Invoke-Correcao 'I' 'Unidades mapeadas' ("remover mapeamento quebrado {0} -> {1} [{2}]" -f $m.LocalPath, $m.RemotePath, $m.Status) {
                & net use $m.LocalPath /delete /y | Out-Null
            } { $true }
        }
    }

    # 7) Cache DNS
    if ($script:DnsFalhou -and $Servidor) {
        Invoke-Correcao 'IV' 'Resolucao DNS' 'limpar cache DNS e tentar resolver de novo' {
            Clear-DnsClientCache
        } {
            try { [void][System.Net.Dns]::GetHostAddresses($Servidor); $true } catch { $false }
        }
    }

    # 8) Opt-in: LocalAccountTokenFilterPolicy
    if ($latfp -ne 1) {
        if ($PermitirAdminRemoto) {
            Invoke-Correcao 'III' 'LocalAccountTokenFilterPolicy (esta maquina)' 'definir 1 (permite token administrativo completo na rede com contas locais)' {
                Set-RegDword $polSys 'LocalAccountTokenFilterPolicy' 1
            } {
                [int](Get-RegValor $polSys 'LocalAccountTokenFilterPolicy') -eq 1
            }
        }
        elseif ($compAdmin) {
            Add-Correcao 'III' 'LocalAccountTokenFilterPolicy (esta maquina)' 'MANUAL' 'nao alterado (reduz a seguranca). No SERVIDOR de destino, rode com -PermitirAdminRemoto se quiser usar C$/ADMIN$ com conta local.'
        }
    }

    # 9) Opt-in: conta local
    $ic = $script:InfoContaLocal
    if ($CorrigirConta -and $ic -and $ic.Existe) {
        $nc = $ic.Nome
        $itemConta = "Conta '$nc' em esta maquina"
        if ($ic.Desabilitada) {
            Invoke-Correcao 'I' $itemConta 'habilitar conta local' { Enable-LocalUser -Name $nc -ErrorAction Stop } { -not (Get-InfoUsuarioLocal $nc).Desabilitada }
        }
        if ($ic.Bloqueada) {
            Invoke-Correcao 'I' $itemConta 'desbloquear conta local' { & net user $nc /active:yes | Out-Null } { -not (Get-InfoUsuarioLocal $nc).Bloqueada }
        }
        if ($ic.ContaExpiraEm -and $ic.ContaExpiraEm -lt (Get-Date)) {
            Invoke-Correcao 'I' $itemConta 'remover expiracao da conta' { Set-LocalUser -Name $nc -AccountNeverExpires -ErrorAction Stop } { $null -eq (Get-InfoUsuarioLocal $nc).ContaExpiraEm }
        }
        if (($ic.SenhaExpiraEm -and $ic.SenhaExpiraEm -lt (Get-Date)) -or $ic.SenhaObrigatoria -eq $false) {
            Add-Correcao 'I' $itemConta 'MANUAL' "senha expirada/ausente: defina uma senha real com  net user $nc *  (o script nunca altera senhas)"
        }
    }

    # 10) Opt-in: canal seguro
    if ($ReparCanalSeguro -and $emDominio -and $script:CanalOk -eq $false) {
        if (-not $CredencialDominio) {
            Add-Correcao 'V' 'Test-ComputerSecureChannel' 'MANUAL' 'informe -CredencialDominio (Get-Credential) para reparar o canal seguro'
        }
        else {
            Invoke-Correcao 'V' 'Test-ComputerSecureChannel' 'reparar canal seguro com o dominio' {
                if (-not (Test-ComputerSecureChannel -Repair -Credential $CredencialDominio)) { throw 'reparo nao confirmado' }
            } {
                [bool](Test-ComputerSecureChannel)
            }
        }
    }

    # 11) Opt-in: perfil de rede Publica -> Privada
    if ($DefinirRedePrivada) {
        foreach ($pp in $script:PerfisPublicos) {
            Invoke-Correcao 'Rede' 'Perfil de rede' ("'{0}' (interface {1}): Publica -> Privada" -f $pp.Name, $pp.InterfaceIndex) {
                $script:Backup.Add([pscustomobject]@{ Tipo = 'PerfilRede'; InterfaceIndex = $pp.InterfaceIndex; Categoria = 'Public' }); Save-Backup
                Set-NetConnectionProfile -InterfaceIndex $pp.InterfaceIndex -NetworkCategory Private -ErrorAction Stop
            } {
                (Get-NetConnectionProfile -InterfaceIndex $pp.InterfaceIndex).NetworkCategory.ToString() -eq 'Private'
            }
        }
    }

    # 12) Opt-in: firewall do SMB, descoberta de rede e servicos (nunca em rede Publica)
    if ($HabilitarCompartilhamento) {
        $alvoPerf = Get-PerfisFwAtivos -SemPublico
        if ($alvoPerf.Count -eq 0) {
            Add-Correcao 'Rede' 'Compartilhamento de arquivos (firewall)' 'MANUAL' 'nenhuma rede Privada/Dominio ativa (so Publica ou desconectado). Use -DefinirRedePrivada em rede confiavel e rode de novo.'
        }
        else {
            $lista = @()
            $regraSmb2 = $null
            try { $regraSmb2 = Get-NetFirewallRule -Name 'FPS-SMB-In-TCP' -ErrorAction Stop } catch { }
            if ($regraSmb2 -and -not (Test-RegraAtivaNoPerfil $regraSmb2 $alvoPerf)) { $lista += [pscustomobject]@{ Item = 'Compartilhamento de arquivos (firewall)'; Regra = $regraSmb2 } }
            foreach ($rr in @(Get-RegrasFw)) { if (-not (Test-RegraAtivaNoPerfil $rr $alvoPerf)) { $lista += [pscustomobject]@{ Item = 'Descoberta de rede (firewall)'; Regra = $rr } } }
            foreach ($it in $lista) {
                $rg = $it.Regra
                Invoke-Correcao 'Rede' $it.Item ("habilitar regra '{0}' [{1}] para {2}" -f $rg.DisplayName, $rg.Name, ($alvoPerf -join '/')) {
                    $script:Backup.Add([pscustomobject]@{ Tipo = 'FirewallRegra'; Nome = $rg.Name; Habilitada = $rg.Enabled.ToString(); Perfil = $rg.Profile.ToString() }); Save-Backup
                    if ($rg.Profile.ToString() -match 'Any') { Set-NetFirewallRule -Name $rg.Name -Enabled True -ErrorAction Stop }
                    else { Set-NetFirewallRule -Name $rg.Name -Enabled True -Profile (@($rg.Profile.ToString() -split ',\s*') + @($alvoPerf) | Select-Object -Unique) -ErrorAction Stop }
                } {
                    Test-RegraAtivaNoPerfil (Get-NetFirewallRule -Name $rg.Name) $alvoPerf
                }
            }
            foreach ($svc in $script:ServDescoberta) {
                Invoke-Correcao 'Rede' 'Descoberta de rede (servicos)' "servico $svc : Automatico + iniciar" {
                    Backup-Servico $svc
                    Set-Service -Name $svc -StartupType Automatic -ErrorAction Stop
                    Start-Service -Name $svc -ErrorAction Stop
                } {
                    (Get-Service -Name $svc).Status -eq 'Running'
                }
            }
        }
    }

    # 13) Opt-ins que REDUZEM a seguranca (dispositivos legados)
    $regSmbCli = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    if ($PermitirConvidadoInseguro -and $cli -and -not $cli.EnableInsecureGuestLogons) {
        Invoke-Correcao 'SMB' 'Cliente: logons de convidado inseguros' 'AllowInsecureGuestAuth=1 (REDUZ a seguranca; so para NAS/TV/PC sem senha)' {
            Set-RegDword $regSmbCli 'AllowInsecureGuestAuth' 1
        } {
            [bool](Get-SmbClientConfiguration).EnableInsecureGuestLogons
        }
    }
    if ($RelaxarAssinaturaCliente -and $cli -and $cli.RequireSecuritySignature) {
        Invoke-Correcao 'SMB' 'Cliente: assinatura exigida' 'RequireSecuritySignature 1 -> 0 (REDUZ a seguranca; a assinatura continua habilitada)' {
            Set-RegDword $regSmbCli 'RequireSecuritySignature' 0
        } {
            -not (Get-SmbClientConfiguration).RequireSecuritySignature
        }
    }

    # 11) Componentes do adaptador desabilitados
    foreach ($bd in $script:BindingsOff) {
        $itemB = "Binding $($bd.Id) em $($bd.Adaptador)"
        Invoke-Correcao 'Basico' $itemB ("habilitar {0} no adaptador '{1}'" -f $bd.Id, $bd.Adaptador) {
            $script:Backup.Add([pscustomobject]@{ Tipo = 'Binding'; Adaptador = $bd.Adaptador; Id = $bd.Id; Enabled = $false }); Save-Backup
            Enable-NetAdapterBinding -Name $bd.Adaptador -ComponentID $bd.Id -ErrorAction Stop
        } {
            [bool](Get-NetAdapterBinding -Name $bd.Adaptador -ComponentID $bd.Id).Enabled
        }
    }

    # 12) Opt-in: rede Publica -> Privada + regras de firewall de compartilhamento/descoberta
    if ($AjustarRede) {
        foreach ($pf in $script:PerfisPublicos) {
            Invoke-Correcao 'Basico' 'Perfil de rede' ("rede '{0}' ({1}): Public -> Private" -f $pf.Name, $pf.InterfaceAlias) {
                $script:Backup.Add([pscustomobject]@{ Tipo = 'PerfilRede'; Indice = $pf.InterfaceIndex; Categoria = 'Public' }); Save-Backup
                Set-NetConnectionProfile -InterfaceIndex $pf.InterfaceIndex -NetworkCategory Private -ErrorAction Stop
            } {
                [string](Get-NetConnectionProfile -InterfaceIndex $pf.InterfaceIndex).NetworkCategory -eq 'Private'
            }
        }
        $catsAgora = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.NetworkCategory })
        $privadoDepois = ($catsAgora -contains 'Private') -or ($catsAgora -contains 'DomainAuthenticated') -or ($Simular -and $script:PerfisPublicos.Count -gt 0)
        if ($privadoDepois) {
            $smR = @(Get-NetFirewallRule -Name 'FPS-SMB-In-TCP' -ErrorAction SilentlyContinue | Where-Object { [string]$_.Enabled -eq 'False' })
            $dnR = @(Get-RegrasGrupo $gNet 'Network Discovery|Descoberta de Rede' | Where-Object { [string]$_.Enabled -eq 'False' -and ([string]$_.Profile -match 'Private|Domain|Any') } | Sort-Object Name -Unique)
            Invoke-HabilitarRegras 'Firewall: Compartilhamento de arquivos e impressoras (SMB-In)' $smR
            Invoke-HabilitarRegras 'Firewall: Descoberta de rede' $dnR
        }
        else { Add-Correcao 'Basico' 'Firewall' 'MANUAL' 'a rede continua Publica: regras de firewall nao foram habilitadas (por seguranca).' }
    }

    # Pendencias que exigem acao manual
    $tratados = @($script:Correcoes | Where-Object { $_.Status -in 'CORRIGIDO', 'SIMULADO', 'NAO-VERIFICADO' } | ForEach-Object { $_.Item })
    $pend = @($script:Resultados | Where-Object { $_.Fase -eq 'diag' -and ($_.Status -eq 'FALHA' -or $_.Status -eq 'ALERTA') -and ($tratados -notcontains $_.Item) })
    if ($pend.Count -gt 0) {
        Write-Host ''
        Write-Host 'PENDENTE (o script nao corrige automaticamente):' -ForegroundColor Yellow
        foreach ($x in $pend) {
            Write-Host ("  [{0}] {1}: {2}" -f $x.Vetor, $x.Item, $x.Detalhe) -ForegroundColor Yellow
            if ($x.Correcao) { Write-Host ("      orientacao: {0}" -f $x.Correcao) -ForegroundColor DarkGray }
        }
    }

    $aplicadas = @($script:Correcoes | Where-Object Status -eq 'CORRIGIDO').Count
    if (-not $Simular) {
        if ($script:Backup.Count -gt 0) {
            Write-Host ''
            Write-Host ("Backup dos valores anteriores: {0}" -f $BackupPath) -ForegroundColor White
            Write-Host ("Para desfazer:  .\Diagnostico-Erro86.ps1 -Restaurar '{0}'" -f $BackupPath) -ForegroundColor White
        }
        if ($aplicadas -gt 0) {
            Write-Host 'Dica: LmCompatibilityLevel pode so valer para novos logons/servicos. Se ainda falhar, bloqueie e desbloqueie a sessao ou reinicie o PC.' -ForegroundColor DarkGray
            Invoke-BlocoTesteAtivo ' - REVERIFICACAO APOS CORRECOES'
        }
    }
}

# ----------------------------------------------------------------------------
Titulo 'RESUMO'
# ----------------------------------------------------------------------------
$falhas = @($script:Resultados | Where-Object { $_.Fase -eq 'diag' -and $_.Status -eq 'FALHA' })
$alertas = @($script:Resultados | Where-Object { $_.Fase -eq 'diag' -and $_.Status -eq 'ALERTA' })
$oks = @($script:Resultados | Where-Object { $_.Fase -eq 'diag' -and $_.Status -eq 'OK' })
Write-Host ("OK: {0}   ALERTA: {1}   FALHA: {2}" -f $oks.Count, $alertas.Count, $falhas.Count) -ForegroundColor White
if ($falhas.Count -gt 0) {
    Write-Host ''
    Write-Host 'FALHAS (provaveis causas, resolva primeiro):' -ForegroundColor Red
    $falhas | ForEach-Object {
        Write-Host ("  [{0}] {1}: {2}" -f $_.Vetor, $_.Item, $_.Detalhe) -ForegroundColor Red
        if ($_.Correcao) { Write-Host ("      correcao: {0}" -f $_.Correcao) -ForegroundColor DarkGray }
    }
}
if ($alertas.Count -gt 0) {
    Write-Host ''
    Write-Host 'ALERTAS (contribuintes possiveis):' -ForegroundColor Yellow
    $alertas | ForEach-Object {
        Write-Host ("  [{0}] {1}: {2}" -f $_.Vetor, $_.Item, $_.Detalhe) -ForegroundColor Yellow
        if ($_.Correcao) { Write-Host ("      correcao: {0}" -f $_.Correcao) -ForegroundColor DarkGray }
    }
}
if (-not $Corrigir -and ($falhas.Count -gt 0 -or $alertas.Count -gt 0)) {
    Write-Host ''
    Write-Host 'Para aplicar as correcoes seguras: rode com -Simular (previa) e depois com -Corrigir. Um backup para desfazer e gerado.' -ForegroundColor Cyan
}
if ($Corrigir) {
    $nOk = @($script:Correcoes | Where-Object Status -eq 'CORRIGIDO').Count
    $nFalhou = @($script:Correcoes | Where-Object Status -eq 'FALHOU').Count
    $nSim = @($script:Correcoes | Where-Object Status -eq 'SIMULADO').Count
    Write-Host ("Correcoes: aplicadas={0} simuladas={1} falharam={2}" -f $nOk, $nSim, $nFalhou) -ForegroundColor White
}
if ($falhas.Count -eq 0 -and $alertas.Count -eq 0) {
    Write-Host 'Nenhuma causa evidente encontrada nesta maquina. Rode no SERVIDOR tambem (ou com -TentarRemoto) e use -Credencial para o teste ativo.' -ForegroundColor Green
}

try {
    $cab = "DIAGNOSTICO ERRO 86 - $(Get-Date) - Maquina: $env:COMPUTERNAME - Alvo: $Servidor - Usuario: $Usuario`r`n"
    $txt = $cab + ($script:Resultados | Format-List Fase, Vetor, Item, Status, Detalhe, Correcao | Out-String -Width 250)
    if ($script:Correcoes.Count -gt 0) { $txt += "`r`n=== CORRECOES ===`r`n" + ($script:Correcoes | Format-List Vetor, Item, Status, Detalhe | Out-String -Width 250) }
    if (Test-Path $BackupPath) { $txt += "`r`nBackup para desfazer: $BackupPath`r`n" }
    $txt | Out-File -FilePath $Relatorio -Encoding UTF8
    Write-Host ''
    Write-Host ("Relatorio salvo em: {0}" -f $Relatorio) -ForegroundColor White
}
catch { Write-Host "Nao foi possivel salvar o relatorio: $($_.Exception.Message)" -ForegroundColor Yellow }
