#!/bin/bash

echo "보안 점검 스크립트"
echo "============================="

# 계정 관리 점검 함수들
check_root_login() {
    echo "U-01: root 계정 원격 접속 제한 점검"
    if [ -f /etc/ssh/sshd_config ] && grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
        echo "[양호] root 계정의 SSH 원격 접속이 제한되어 있습니다."
    else
        echo "[취약] root 계정의 SSH 원격 접속이 허용되어 있습니다."
    fi
}

check_password_complexity() {
    echo "U-02: 패스워드 복잡성 설정 점검"
    if grep -q "pam_pwquality.so" /etc/pam.d/common-password || grep -q "pam_cracklib.so" /etc/pam.d/common-password; then
        echo "[양호] 패스워드 복잡성 정책이 설정되어 있습니다."
    else
        echo "[취약] 패스워드 복잡성 정책이 설정되어 있지 않습니다."
    fi
}

check_account_lockout() {
    echo "U-03: 계정 잠금 임계값 설정 점검"
    if grep -q "pam_tally2.so" /etc/pam.d/common-auth || grep -q "pam_faillock.so" /etc/pam.d/common-auth; then
        echo "[양호] 계정 잠금 정책이 설정되어 있습니다."
    else
        echo "[취약] 계정 잠금 정책이 설정되어 있지 않습니다."
    fi
}

check_password_file_protection() {
    echo "U-04: 패스워드 파일 보호 점검"
    if [ "$(stat -c %a /etc/shadow)" = "400" ]; then
        echo "[양호] shadow 파일의 권한이 적절히 설정되어 있습니다."
    else
        echo "[취약] shadow 파일의 권한이 취약합니다."
    fi
}

check_uid_zero() {
    echo "U-05: root 이외의 UID '0' 점검"
    uid_zero=$(awk -F: '($3 == 0) {print $1}' /etc/passwd | grep -v root)
    if [ -n "$uid_zero" ]; then
        echo "[취약] root 이외에 UID가 0인 계정이 존재합니다: $uid_zero"
    else
        echo "[양호] root 이외에 UID가 0인 계정이 없습니다."
    fi
}

check_su_restriction() {
    echo "U-06: root 계정 su 제한 점검"
    if grep -q "auth required pam_wheel.so use_uid" /etc/pam.d/su; then
        echo "[양호] su 명령어 사용이 특정 그룹으로 제한되어 있습니다."
    else
        echo "[취약] su 명령어 사용 제한이 설정되어 있지 않습니다."
    fi
}

check_password_policy() {
    echo "U-07~U-09: 패스워드 정책 점검"
    local min_len=$(grep "^PASS_MIN_LEN" /etc/login.defs | awk '{print $2}')
    local max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
    local min_days=$(grep "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}')

    [ -n "$min_len" ] && [ "$min_len" -ge 8 ] && echo "[양호] 최소 길이: $min_len" || echo "[취약] 최소 길이 설정 필요"
    [ -n "$max_days" ] && [ "$max_days" -le 90 ] && echo "[양호] 최대 사용 기간: $max_days" || echo "[취약] 최대 사용 기간 설정 필요"
    [ -n "$min_days" ] && [ "$min_days" -ge 1 ] && echo "[양호] 최소 사용 기간: $min_days" || echo "[취약] 최소 사용 기간 설정 필요"
}

check_unnecessary_accounts() {
    echo "U-10: 불필요한 계정 제거 점검"
    unnecessary_accounts=$(awk -F: '($3 >= 1000) {print $1}' /etc/passwd | grep -vE "^($(awk -F: '($3 >= 1000) {print $1}' /etc/passwd | xargs -I {} getent group {} | cut -d: -f1 | tr '\n' '|' | sed 's/|$//'))")
    if [ -n "$unnecessary_accounts" ]; then
        echo "[취약] 다음 불필요한 계정이 존재합니다: $unnecessary_accounts"
    else
        echo "[양호] 불필요한 계정이 존재하지 않습니다."
    fi
}

check_admin_group() {
    echo "U-11: 관리자 그룹 계정 점검"
    admin_accounts=$(grep "^wheel" /etc/group | cut -d: -f4)
    admin_count=$(echo "$admin_accounts" | tr ',' '\n' | wc -l)
    if [ "$admin_count" -le 2 ]; then
        echo "[양호] 관리자 그룹에 한의 계정만 포함되어 있습니다: $admin_accounts"
    else
        echo "[취약] 관리자 그룹에 불필요하게 많은 계정 포함되어 있습니다: $admin_accounts"
    fi
}
check_invalid_gid() {
    echo "U-12: 계정이 존재하지 않는 GID 점검"
    invalid_gids=$(cut -d: -f4 /etc/passwd | sort -u | while read gid; do
        if ! grep -q ":$gid:" /etc/group; then
            echo $gid
        fi
    done)
    if [ -n "$invalid_gids" ]; then
        echo "[취약] 다음 GID에 해당하는 그룹이 존재하지 않습니다: $invalid_gids"
    else
        echo "[양호] 모든 GID가 유효한 그룹에 매핑되어 있습니다."
    fi
}

check_duplicate_uid() {
    echo "U-13: 동일한 UID 점검"
    duplicate_uids=$(cut -d: -f3 /etc/passwd | sort | uniq -d)
    if [ -n "$duplicate_uids" ]; then
        echo "[취약] 다음 UID가 중복되어 사용되고 있습니다: $duplicate_uids"
    else
        echo "[양호] 중복된 UID가 없습니다."
    fi
}

check_user_shell() {
    echo "U-14: 사용자 shell 점검"
    invalid_shells=$(grep -v '^#' /etc/passwd | awk -F: '$7!="/sbin/nologin" && $7!="/bin/false" && $7!="/bin/bash" && $7!="/bin/sh" {print $1 ":" $7}')
    if [ -n "$invalid_shells" ]; then
        echo "[취약] 다음 사용자의 shell이 적절하지 않습니다:"
        echo "$invalid_shells"
    else
        echo "[양호] 모든 사용자의 shell이 적절하게 설정되어 있습니다."
    fi
}

check_session_timeout() {
    echo "U-15: Session Timeout 설정 점검"
    if grep -q "TMOUT=" /etc/profile; then
        timeout_value=$(grep "TMOUT=" /etc/profile | cut -d= -f2)
        if [ "$timeout_value" -le 600 ]; then
            echo "[양호] Session Timeout이 적절히 설정되어 있습니다: $timeout_value 초"
        else
            echo "[취약] Session Timeout이 600초(10분)보다 길게 설정되어 있습니다: $timeout_value 초"
        fi
    else
        echo "[취약] Session Timeout이 설정되어 있지 않습니다."
    fi
}

check_root_path() {
    echo "U-16: root 홈, 패스 디렉터리 권한 및 패스 설정 점검"
    if [ "$(stat -c %a /root)" = "700" ]; then
        echo "[양호] root 홈 디렉터리의 권한이 적절히 설정되어 있습니다."
    else
        echo "[취약] root 홈 디렉터리의 권한 설정이 부적절합니다."
    fi
    if echo $PATH | grep -q "::"; then
    echo "[취약] PATH 환경변수에 '::' 가 포함되어 있습니다."
    else
    echo "[양호] PATH 환경변수가 적절히 설정되어 있습니다."
    fi
    }

check_file_ownership() {
    echo "U-17: 파일 및 디렉터리 소유자 설정 점검"
    unowned_files=$(find / -nouser -o -nogroup 2>/dev/null)
    if [ -n "$unowned_files" ]; then
        echo "[취약] 소유자나 그룹이 존재하지 않는 파일이 있습니다:"
        echo "$unowned_files"
    else
        echo "[양호] 모든 파일 및 디렉터리에 유효한 소유자와 그룹이 설정되어 있습니다."
    fi
}

check_passwd_file() {
    echo "U-18: /etc/passwd 파일 소유자 및 권한 설정 점검"
    passwd_perm=$(stat -c %a /etc/passwd)
    passwd_owner=$(stat -c %U /etc/passwd)
    if [ "$passwd_perm" = "644" ] && [ "$passwd_owner" = "root" ]; then
        echo "[양호] /etc/passwd 파일의 소유자 및 권한이 적절히 설정되어 있습니다."
    else
        echo "[취약] /etc/passwd 파일의 소유자 또는 권한 설정이 부적절합니다."
    fi
}

check_shadow_file() {
    echo "U-19: /etc/shadow 파일 소유자 및 권한 설정 점검"
    shadow_perm=$(stat -c %a /etc/shadow)
    shadow_owner=$(stat -c %U /etc/shadow)
    if [ "$shadow_perm" = "400" ] && [ "$shadow_owner" = "root" ]; then
        echo "[양호] /etc/shadow 파일의 소유자 및 권한이 적절히 설정되어 니다."
    else
        echo "[취약] /etc/shadow 파일의 소유자 또는 권한 설정이 부적절합니다."
    fi
}

check_hosts_file() {
    echo "U-20: /etc/hosts 파일 소유자 및 권한 설정 점검"
    hosts_perm=$(stat -c %a /etc/hosts)
    hosts_owner=$(stat -c %U /etc/hosts)
    if [ "$hosts_perm" = "644" ] && [ "$hosts_owner" = "root" ]; then
        echo "[양호] /etc/hosts 파일의 소유자 및 권한이 적절히 설정되어 있습니다."
    else
        echo "[취약] /etc/hosts 파일의 소유자 또는 권한 설정이 부적절합니다."
    fi
}

check_inetd_services() {
    echo "U-21: /etc/inetd.conf 파일의 소유자 및 권한 설정 점검"
    if [ -f /etc/inetd.conf ]; then
        inetd_perm=$(stat -c %a /etc/inetd.conf)
        inetd_owner=$(stat -c %U /etc/inetd.conf)
        if [ "$inetd_perm" = "600" ] && [ "$inetd_owner" = "root" ]; then
            echo "[양호] /etc/inetd.conf 파일의 소유자 및 권한이 적절히 설정되어 있습니다."
        else
            echo "[취약] /etc/inetd.conf 파일의 소유자 또는 권한 설정이 부적절합니다."
        fi
    else
        echo "[정보] /etc/inetd.conf 파일이 존재하지 않습니다."
    fi
}

check_syslog_conf() {
    echo "U-22: /etc/(r)syslog.conf 파일 소유자 및 권한 설정 점검"
    
    # rsyslog.conf와 syslog.conf 파일 중 존재하는 것을 확인
    if [ -f /etc/rsyslog.conf ]; then
        syslog_file="/etc/rsyslog.conf"
    elif [ -f /etc/syslog.conf ]; then
        syslog_file="/etc/syslog.conf"
    else
        echo "[취약] syslog 설정 파일을 찾을 수 없습니다."
        return
    fi
    
    syslog_perm=$(stat -c %a "$syslog_file")
    syslog_owner=$(stat -c %U "$syslog_file")
    
    if [ "$syslog_perm" = "640" ] && [ "$syslog_owner" = "root" ]; then
        echo "[양호] $syslog_file 파일의 소유자 및 권한이 적절히 설정되어 있습니다."
    else
        echo "[취약] $syslog_file 파일의 소유자 또는 권한 설정이 부적절합니다."
        echo "  현재 설정: 소유자=$syslog_owner, 권한=$syslog_perm"
        echo "  권장 설정: 소유자=root, 권한=640"
    fi
}

check_services_file() {
    echo "U-23: /etc/services 파일 소유자 및 권한 설정 점검"
    
    if [ -f /etc/services ]; then
        services_perm=$(stat -c %a /etc/services)
        services_owner=$(stat -c %U /etc/services)
        services_group=$(stat -c %G /etc/services)
        
        if [ "$services_perm" = "644" ] && [ "$services_owner" = "root" ] && [ "$services_group" = "root" ]; then
            echo "[양호] /etc/services 파일의 소유자, 그룹 및 권한이 적절히 설정되어 있습니다."
        else
            echo "[취약] /etc/services 파일의 소유자, 그룹 또는 권한 설정이 부적절합니다."
            echo "  현재 설정: 소유자=$services_owner, 그룹=$services_group, 권한=$services_perm"
            echo "  권장 설정: 소유자=root, 그룹=root, 권한=644"
        fi
    else
        echo "[취약] /etc/services 파일이 존재하지 않습니다."
    fi
}
check_suid_sgid_sticky() {
    echo "U-24: SUID, SGID, Stick bit 설정 파일 점검"
    suspicious_files=$(find / -type f \( -perm -04000 -o -perm -02000 -o -perm -01000 \) 2>/dev/null)
    if [ -z "$suspicious_files" ]; then
        echo "[양호] SUID, SGID, Sticky bit가 설정된 의심스러운 파일이 없습니다."
    else
        echo "[취약] 다음 파일들의 SUID, SGID, Sticky bit 설정을 확인하세요:"
        echo "$suspicious_files"
    fi
}

check_startup_files() {
    echo "U-25: 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정"
    startup_files=("/etc/profile" "/etc/bashrc" "/etc/bash.bashrc" "/etc/csh.cshrc" "/etc/csh.login")
    for file in "${startup_files[@]}"; do
        if [ -f "$file" ]; then
            owner=$(stat -c %U "$file")
            perm=$(stat -c %a "$file")
            if [ "$owner" = "root" ] && [ "$perm" -le "644" ]; then
                echo "[양호] $file 의 소유자와 권한이 적절히 설정되어 있습니다."
            else
                echo "[취약] $file 의 소유자 또는 권한 설정을 확인하세요."
            fi
        fi
    done
}

check_world_writable() {
    echo "U-26: world writable 파일 점검"
    world_writable=$(find / -type f -perm -002 2>/dev/null)
    if [ -z "$world_writable" ]; then
        echo "[양호] world writable 파일이 없습니다."
    else
        echo "[취약] 다음 world writable 파일들을 확인하세요:"
        echo "$world_writable"
    fi
}

check_dev_files() {
    echo "U-27: /dev에 존재하지 않는 device 파일 제거"
    invalid_devices=$(find /dev -type f 2>/dev/null)
    if [ -z "$invalid_devices" ]; then
        echo "[양호] /dev 디렉터리에 일반 파일이 없습니다."
    else
        echo "[취약] /dev 디렉터리에 다음 일반 파일들이 존재합니다. 제거를 고려하세요:"
        echo "$invalid_devices"
    fi
}

check_rhosts_equiv() {
    echo "U-28: $HOME/.rhosts, hosts.equiv 사용 금지"
    if [ -f /etc/hosts.equiv ]; then
        echo "[취약] /etc/hosts.equiv 파일이 존재합니다. 제거를 고려하세요."
    else
        echo "[양호] /etc/hosts.equiv 파일이 존재하지 않습니다."
    fi
    rhosts=$(find /home -name .rhosts 2>/dev/null)
    if [ -n "$rhosts" ]; then
        echo "[취약] 다음 .rhosts 파일들이 존재합니다. 제거를 고려하세요:"
        echo "$rhosts"
    else
        echo "[양호] 사용자 홈 디렉터리에 .rhosts 파일이 없습니다."
    fi
}

check_ip_port_restriction() {
    echo "U-29: 접속 IP 및 포트 제한"
    if [ -f /etc/hosts.allow ] && [ -f /etc/hosts.deny ]; then
        echo "[양호] TCP Wrapper가 구성되어 있습니다. 설정을 확인하세요."
    else
        echo "[취약] TCP Wrapper 설정 파일이 없습니다. 접속 제한 설정을 검토하세요."
    fi
}

check_hosts_lpd() {
    echo "U-30: hosts.lpd 파일 소유자 및 권한 설정"
    if [ -f /etc/hosts.lpd ]; then
        owner=$(stat -c %U /etc/hosts.lpd)
        perm=$(stat -c %a /etc/hosts.lpd)
        if [ "$owner" = "root" ] && [ "$perm" -le "644" ]; then
            echo "[양호] hosts.lpd 파일의 소유자와 권한이 적절히 설정되어 있습니다."
        else
            echo "[취약] hosts.lpd 파일의 소유자 또는 권한 설정을 확인하세요."
        fi
    else
        echo "[정보] hosts.lpd 파일이 존재하지 않습니다."
    fi
}

check_nis_service() {
    echo "U-31: NIS 서비스 비활성화"
    if systemctl is-active --quiet ypserv; then
        echo "[취약] NIS 서비스가 활성화되어 있습니다."
    else
        echo "[양호] NIS 서비스가 비활성화되어 있습니다."
    fi
}

check_umask() {
    echo "U-32: umask 설정 관리"
    system_umask=$(grep "^umask" /etc/profile | awk '{print $2}')
    if [ "$system_umask" = "022" ] || [ "$system_umask" = "027" ]; then
        echo "[양호] 시스템 umask가 적절히 설정되어 있습니다: $system_umask"
    else
        echo "[취약] 시스템 umask 설정을 확인하세요: $system_umask"
    fi
}

check_home_directories() {
    echo "U-33: 홈 디렉터리 소유자 및 권한 설정"
    for dir in /home/*; do
        if [ -d "$dir" ]; then
            owner=$(stat -c %U "$dir")
            perm=$(stat -c %a "$dir")
            if [ "$owner" = "$(basename "$dir")" ] && [ "$perm" -le "755" ]; then
                echo "[양호] $dir 의 소유자와 권한이 적절히 설정되어 있습니다."
            else
                echo "[취약] $dir 의 소유자 또는 권한 설정을 확인하세요."
            fi
        fi
    done
}

check_home_directory_existence() {
    echo "U-34: 홈 디렉터리로 지정한 디렉터리의 존재 관리"
    while IFS=: read -r username _ _ _ _ homedir _; do
        if [ ! -d "$homedir" ]; then
            echo "[취약] 사용자 $username 의 홈 디렉터리 $homedir 가 존재하지 않습니다."
        fi
    done < /etc/passwd
}

check_hidden_files() {
    echo "U-35: 숨겨진 파일 및 디렉터리 검색 및 제거"
    hidden_files=$(find / -name ".*" -type f 2>/dev/null)
    if [ -n "$hidden_files" ]; then
        echo "[주의] 다음 숨겨진 파일들이 발견되었습니다. 검토 후 필요 없는 파일은 제거하세요:"
        echo "$hidden_files"
    else
        echo "[양호] 숨겨진 파일이 발견되지 않았습니다."
    fi
}

check_finger_service() {
    echo "U-36: Finger 서비스 비활성화 점검"
    if systemctl is-active --quiet finger; then
        echo "[취약] Finger 서비스가 활성화되어 있습니다."
    else
        echo "[양호] Finger 서비스가 비활성화되어 있습니다."
    fi
}

check_anonymous_ftp() {
    echo "U-37: Anonymous FTP 비활성화 점검"
    if grep -qi "^anonymous_enable=YES" /etc/vsftpd.conf 2>/dev/null; then
        echo "[취약] Anonymous FTP가 활성화되어 있습니다."
    else
        echo "[양호] Anonymous FTP가 비활성화되어 있거나 설정 파일이 없습니다."
    fi
}

check_r_services() {
    echo "U-38: r 계열 서비스 비활성화 점검"
    r_services=("rsh" "rlogin" "rexec")
    for service in "${r_services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            echo "[취약] $service 서비스가 활성화되어 있습니다."
        else
            echo "[양호] $service 서비스가 비활성화되어 있습니다."
        fi
    done
}
check_dos_service() {
    echo "U-40: DoS 공격에 취약한 서비스 비활성화 점검"
    dos_vulnerable_services=("echo" "discard" "daytime" "chargen")
    for service in "${dos_vulnerable_services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            echo "[취약] $service 서비스가 활성화되어 있습니다."
        else
            echo "[양호] $service 서비스가 비활성화되어 있습니다."
        fi
    done
}

check_nfs_service() {
    echo "U-41: NFS 서비스 비활성화 점검"
    if systemctl is-active --quiet nfs-server; then
        echo "[취약] NFS 서비스가 활성화되어 있습니다."
    else
        echo "[양호] NFS 서비스가 비활성화되어 있습니다."
    fi
}

check_nfs_access() {
    echo "U-42: NFS 접근 통제 점검"
    if [ -f /etc/exports ]; then
        insecure_exports=$(grep -v '^#' /etc/exports | grep -v 'sec=krb5')
        if [ -z "$insecure_exports" ]; then
            echo "[양호] 모든 NFS 공유가 Kerberos 인증을 사용하고 있습니다."
        else
            echo "[취약] 다음 NFS 공유의 보안 설정을 확인하세요:"
            echo "$insecure_exports"
        fi
    else
        echo "[정보] NFS 설정 파일이 존재하지 않습니다."
    fi
}

check_automounter() {
    echo "U-43: automountd 제거 점검"
    if systemctl is-active --quiet autofs; then
        echo "[취약] automounter 서비스가 활성화되어 있습니다."
    else
        echo "[양호] automounter 서비스가 비활성화되어 있습니다."
    fi
}

check_rpc_service() {
    echo "U-44: RPC 서비스 확인"
    rpc_services=("rpcbind" "rpcinfo")
    for service in "${rpc_services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            echo "[취약] $service 서비스가 활성화되어 있습니다."
        else
            echo "[양호] $service 서비스가 비활성화되어 있습니다."
        fi
    done
}

check_nis_service() {
    echo "U-45: NIS, NIS+ 점검"
    nis_services=("ypserv" "ypbind" "ypxfrd" "rpc.yppasswdd" "rpc.ypupdated")
    for service in "${nis_services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            echo "[취약] $service 서비스가 활성화되어 있습니다."
        else
            echo "[양호] $service 서비스가 비활성화되어 있습니다."
        fi
    done
}

check_tftp_talk() {
    echo "U-46: tftp, talk 서비스 비활성화 점검"
    services=("tftp" "talk")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            echo "[취약] $service 서비스가 활성화되어 있습니다."
        else
            echo "[양호] $service 서비스가 비활성화되어 있습니다."
        fi
    done
}

check_sendmail_version() {
    echo "U-47: Sendmail 버전 점검"
    if command -v sendmail >/dev/null 2>&1; then
        version=$(sendmail -d0.1 < /dev/null | grep -i version | awk '{print $2}')
        echo "[정보] Sendmail 버전: $version"
        echo "[주의] Sendmail 버전이 최신인지 확인하세요."
    else
        echo "[양호] Sendmail이 설치되어 있지 않습니다."
    fi
}

check_spam_relay() {
    echo "U-48: 스팸 메일 릴레이 제한 점검"
    if [ -f /etc/mail/sendmail.cf ]; then
        if grep -q "R$\*" /etc/mail/sendmail.cf && ! grep -q "Promiscuous_Relay" /etc/mail/sendmail.cf; then
            echo "[양호] 스팸 메일 릴레이가 제한되어 있습니다."
        else
            echo "[취약] 스팸 메일 릴레이 설정을 확인하세요."
        fi
    else
        echo "[정보] Sendmail 설정 파일이 존재하지 않습니다."
    fi
}
check_sendmail_user_execution() {
    echo "U-49: 일반 사용자의 Sendmail 실행 방지"
    if [ -f /etc/mail/sendmail.cf ]; then
        if grep -q "PrivacyOptions.*restrictqrun" /etc/mail/sendmail.cf; then
            echo "[양호] Sendmail이 일반 사용자에 의해 실행되지 않도록 설정되어 있습니다."
        else
            echo "[취약] Sendmail 설정에서 일반 사용자의 실행을 제한하도록 설정해야 합니다."
        fi
    else
        echo "[정보] Sendmail 설정 파일이 존재하지 않습니다."
    fi
}

check_dns_security_version() {
    echo "U-50: DNS 보안 버전 패치"
    if command -v named-checkconf >/dev/null 2>&1; then
        version=$(named -v | awk '{print $2}')
        echo "[정보] BIND 버전: $version"
        echo "[주의] BIND 버전이 최신 보안 패치가 적용된 버전인지 확인하세요."
    else
        echo "[정보] DNS 서버(BIND)가 설치되어 있지 않습니다."
    fi
}

check_dns_zone_transfer() {
    echo "U-51: DNS Zone Transfer 설정"
    if [ -f /etc/named.conf ]; then
        if grep -q "allow-transfer" /etc/named.conf; then
            echo "[양호] DNS Zone Transfer가 제한되어 있습니다."
        else
            echo "[취약] DNS Zone Transfer 제한 설정을 확인하세요."
        fi
    else
        echo "[정보] DNS 서버 설정 파일이 존재하지 않습니다."
    fi
}

check_ssh_remote_access() {
    echo "U-59: SSH 원격접속 허용"
    if [ -f /etc/ssh/sshd_config ]; then
        if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
            echo "[양호] root의 SSH 원격 접속이 제한되어 있습니다."
        else
            echo "[취약] root의 SSH 원격 접속 제한을 설정해야 합니다."
        fi
    else
        echo "[정보] SSH 서버 설정 파일이 존재하지 않습니다."
    fi
}

check_ftp_service() {
    echo "U-60: FTP 서비스 확인"
    if systemctl is-active --quiet vsftpd; then
        echo "[주의] FTP 서비스(vsftpd)가 활성화되어 있습니다. 필요성을 검토하세요."
    else
        echo "[양호] FTP 서비스(vsftpd)가 비활성화되어 있습니다."
    fi
}

check_ftp_account_shell() {
    echo "U-61: FTP 계정 shell 제한"
    ftp_users=$(grep ftp /etc/passwd | cut -d: -f1)
    for user in $ftp_users; do
        shell=$(grep "^$user:" /etc/passwd | cut -d: -f7)
        if [ "$shell" != "/sbin/nologin" ] && [ "$shell" != "/bin/false" ]; then
            echo "[취약] FTP 사용자 $user의 셸이 제한되어 있지 않습니다: $shell"
        else
            echo "[양호] FTP 사용자 $user의 셸이 적절히 제한되어 있습니다: $shell"
        fi
    done
}

check_ftpusers_file() {
    echo "U-62: FTPusers 파일 소유자 및 권한 설정"
    if [ -f /etc/ftpusers ]; then
        owner=$(stat -c %U /etc/ftpusers)
        perm=$(stat -c %a /etc/ftpusers)
        if [ "$owner" = "root" ] && [ "$perm" -le "600" ]; then
            echo "[양호] ftpusers 파일의 소유자와 권한이 적절히 설정되어 있습니다."
        else
            echo "[취약] ftpusers 파일의 소유자 또는 권한 설정을 확인하세요."
        fi
    else
        echo "[정보] ftpusers 파일이 존재하지 않습니다."
    fi
}

check_ftpusers_config() {
    echo "U-63: FTPusers 파일 설정"
    if [ -f /etc/ftpusers ]; then
        if grep -q "root" /etc/ftpusers; then
            echo "[양호] root 계정이 FTP 접근에서 제한되어 있습니다."
        else
            echo "[취약] ftpusers 파일에 root 계정을 추가하여 FTP 접근을 제한해야 합니다."
        fi
    else
        echo "[정보] ftpusers 파일이 존재하지 않습니다."
    fi
}

check_at_file_permissions() {
    echo "U-64: at 파일 소유자 및 권한 설정"
    at_files=("/etc/at.allow" "/etc/at.deny")
    for file in "${at_files[@]}"; do
        if [ -f "$file" ]; then
            owner=$(stat -c %U "$file")
            perm=$(stat -c %a "$file")
            if [ "$owner" = "root" ] && [ "$perm" -le "640" ]; then
                echo "[양호] $file 의 소유자와 권한이 적절히 설정되어 있습니다."
            else
                echo "[취약] $file 의 소유자 또는 권한 설정을 확인하세요."
            fi
        else
            echo "[정보] $file 이 존재하지 않습니다."
        fi
    done
}

check_snmp_service() {
    echo "U-65: SNMP 서비스 구동 점검"
    if systemctl is-active --quiet snmpd; then
        echo "[주의] SNMP 서비스가 활성화되어 있습니다. 필요성을 검토하세요."
    else
        echo "[양호] SNMP 서비스가 비활성화되어 있습니다."
    fi
}

check_snmp_community_string() {
    echo "U-66: SNMP 서비스 커뮤니티스트링의 복잡성 설정"
    if [ -f /etc/snmp/snmpd.conf ]; then
        if grep -qE "community.*public|community.*private" /etc/snmp/snmpd.conf; then
            echo "[취약] SNMP 커뮤니티스트링이 기본값(public/private)으로 설정되어 있습니다."
        else
            echo "[양호] SNMP 커뮤니티스트링이 기본값과 다르게 설정되어 있습니다."
        fi
    else
        echo "[정보] SNMP 설정 파일이 존재하지 않습니다."
    fi
}

check_login_warning() {
    echo "U-67: 로그온 시 경고 메시지 제공"
    if [ -f /etc/issue ]; then
        if [ -s /etc/issue ]; then
            echo "[양호] 로그온 경고 메시지가 설정되어 있습니다."
        else
            echo "[취약] /etc/issue 파일이 비어 있습니다. 적절한 경고 메시지를 설정하세요."
        fi
    else
        echo "[취약] /etc/issue 파일이 존재하지 않습니다. 로그온 경고 메시지를 설정하세요."
    fi
}

check_nfs_file_permissions() {
    echo "U-68: NFS 설정 파일 접근 권한"
    nfs_files=("/etc/exports")
    for file in "${nfs_files[@]}"; do
        if [ -f "$file" ]; then
            owner=$(stat -c %U "$file")
            perm=$(stat -c %a "$file")
            if [ "$owner" = "root" ] && [ "$perm" -le "644" ]; then
                echo "[양호] $file 의 소유자와 권한이 적절히 설정되어 있습니다."
            else
                echo "[취약] $file 의 소유자 또는 권한 설정을 확인하세요."
            fi
        else
            echo "[정보] $file 이 존재하지 않습니다."
        fi
    done
}

check_expn_vrfy_commands() {
    echo "U-69: expn, vrfy 명령어 제한"
    if [ -f /etc/mail/sendmail.cf ]; then
        if grep -q "O PrivacyOptions=.*noexpn" /etc/mail/sendmail.cf && grep -q "O PrivacyOptions=.*novrfy" /etc/mail/sendmail.cf; then
            echo "[양호] expn 및 vrfy 명령어가 제한되어 있습니다."
        else
            echo "[취약] sendmail 설정에서 expn 및 vrfy 명령어 제한을 설정해야 합니다."
        fi
    else
        echo "[정보] Sendmail 설정 파일이 존재하지 않습니다."
    fi
}

check_security_patches() {
    echo "U-71: 최신 보안패치 및 벤더 권고사항 적용"
    if command -v yum &> /dev/null; then
        updates=$(yum check-update --security | grep -c '^[a-zA-Z0-9]')
        if [ "$updates" -eq 0 ]; then
            echo "[양호] 시스템이 최신 보안 패치로 업데이트되어 있습니다."
        else
            echo "[취약] $updates 개의 보안 업데이트가 필요합니다."
        fi
    elif command -v apt &> /dev/null; then
        updates=$(apt list --upgradable 2>/dev/null | grep -c security)
        if [ "$updates" -eq 0 ]; then
            echo "[양호] 시스템이 최신 보안 패치로 업데이트되어 있습니다."
        else
            echo "[취약] $updates 개의 보안 업데이트가 필요합니다."
        fi
    else
        echo "[주의] 패키지 관리자를 확인할 수 없습니다. 수동으로 보안 업데이트를 확인하세요."
    fi
}

check_log_review() {
    echo "U-72: 로그의 정기적 검토 및 보고"
    if [ -f /var/log/audit/audit.log ]; then
        last_modified=$(stat -c %Y /var/log/audit/audit.log)
        current_time=$(date +%s)
        days_since_review=$(( (current_time - last_modified) / 86400 ))
        if [ "$days_since_review" -lt 7 ]; then
            echo "[양호] 로그가 최근 7일 이내에 검토되었습니다."
        else
            echo "[취약] 로그가 $days_since_review 일 동안 검토되지 않았습니다."
        fi
    else
        echo "[취약] 감사 로그 파일이 존재하지 않습니다."
    fi
}

# 취약점 카운터 초기화
declare -A vulnerabilities=(
    ["account"]=0
    ["file_dir"]=0
    ["service"]=0
    ["patch"]=0
    ["log"]=0
)
declare -A vulnerability_list

# 취약점 카운트 함수
count_vulnerability() {
    local category=$1
    local result=$2
    local u_number=$3
    if [[ $result == *"[취약]"* ]]; then
        ((vulnerabilities[$category]++))
        vulnerability_list[$category]+="U-$u_number "
    fi
}

# 메인 실행 부분
main() {
    echo "계정 관리 점검 시작"
    count_vulnerability "account" "$(check_root_login)" "01"
    count_vulnerability "account" "$(check_password_complexity)" "02"
    count_vulnerability "account" "$(check_account_lockout)" "03"
    count_vulnerability "account" "$(check_password_file_protection)" "04"
    count_vulnerability "account" "$(check_uid_zero)" "05"
    count_vulnerability "account" "$(check_su_restriction)" "06"
    count_vulnerability "account" "$(check_password_policy)" "07"
    count_vulnerability "account" "$(check_password_policy)" "08"
    count_vulnerability "account" "$(check_password_policy)" "09"
    count_vulnerability "account" "$(check_unnecessary_accounts)" "10"
    count_vulnerability "account" "$(check_admin_group)" "11"
    count_vulnerability "account" "$(check_invalid_gid)" "12"
    count_vulnerability "account" "$(check_duplicate_uid)" "13"
    count_vulnerability "account" "$(check_user_shell)" "14"
    count_vulnerability "account" "$(check_session_timeout)" "15"
    
    echo "파일 및 디렉터리 관리 점검 시작"
    count_vulnerability "file_dir" "$(check_root_path)" "16"
    count_vulnerability "file_dir" "$(check_file_ownership)" "17"
    count_vulnerability "file_dir" "$(check_passwd_file)" "18"
    count_vulnerability "file_dir" "$(check_shadow_file)" "19"
    count_vulnerability "file_dir" "$(check_hosts_file)" "20"
    count_vulnerability "file_dir" "$(check_inetd_services)" "21"
    count_vulnerability "file_dir" "$(check_syslog_conf)" "22"
    count_vulnerability "file_dir" "$(check_services_file)" "23"
    count_vulnerability "file_dir" "$(check_suid_sgid_sticky)" "24"
    count_vulnerability "file_dir" "$(check_startup_files)" "25"
    count_vulnerability "file_dir" "$(check_world_writable)" "26"
    count_vulnerability "file_dir" "$(check_dev_files)" "27"
    count_vulnerability "file_dir" "$(check_rhosts_equiv)" "28"
    count_vulnerability "file_dir" "$(check_ip_port_restriction)" "29"
    count_vulnerability "file_dir" "$(check_hosts_lpd)" "30"
    count_vulnerability "file_dir" "$(check_nis_service)" "31"
    count_vulnerability "file_dir" "$(check_umask)" "32"
    count_vulnerability "file_dir" "$(check_home_directories)" "33"
    count_vulnerability "file_dir" "$(check_home_directory_existence)" "34"
    count_vulnerability "file_dir" "$(check_hidden_files)" "35"
    
    echo "서비스 관리 점검 시작"
    count_vulnerability "service" "$(check_finger_service)" "36"
    count_vulnerability "service" "$(check_anonymous_ftp)" "37"
    count_vulnerability "service" "$(check_r_services)" "38"
    count_vulnerability "service" "$(check_cron_file_permissions)" "39"
    count_vulnerability "service" "$(check_dos_service)" "40"
    count_vulnerability "service" "$(check_nfs_service)" "41"
    count_vulnerability "service" "$(check_nfs_access)" "42"
    count_vulnerability "service" "$(check_automounter)" "43"
    count_vulnerability "service" "$(check_rpc_service)" "44"
    count_vulnerability "service" "$(check_nis_service)" "45"
    count_vulnerability "service" "$(check_tftp_talk)" "46"
    count_vulnerability "service" "$(check_sendmail_version)" "47"
    count_vulnerability "service" "$(check_spam_relay)" "48"
    count_vulnerability "service" "$(check_sendmail_user_execution)" "49"
    count_vulnerability "service" "$(check_dns_security_version)" "50"
    count_vulnerability "service" "$(check_dns_zone_transfer)" "51"
    count_vulnerability "service" "$(check_ssh_remote_access)" "59"
    count_vulnerability "service" "$(check_ftp_service)" "60"
    count_vulnerability "service" "$(check_ftp_account_shell)" "61"
    count_vulnerability "service" "$(check_ftpusers_file)" "62"
    count_vulnerability "service" "$(check_ftpusers_config)" "63"
    count_vulnerability "service" "$(check_at_file_permissions)" "64"
    count_vulnerability "service" "$(check_snmp_service)" "65"
    count_vulnerability "service" "$(check_snmp_community_string)" "66"
    count_vulnerability "service" "$(check_login_warning)" "67"
    count_vulnerability "service" "$(check_nfs_file_permissions)" "68"
    count_vulnerability "service" "$(check_expn_vrfy_commands)" "69"
    
    echo "패치 관리 점검 시작"
    count_vulnerability "patch" "$(check_security_patches)" "71"
    
    echo "로그 관리 점검 시작"
    count_vulnerability "log" "$(check_log_review)" "72"
    
    # 결과 출력
    echo "======== 취약점 요약 ========"
    echo "계정 관리 취약점: ${vulnerabilities[account]}"
    [ ${vulnerabilities[account]} -gt 0 ] && echo "취약한 항목: ${vulnerability_list[account]}"
    echo "파일 및 디렉터리 관리 취약점: ${vulnerabilities[file_dir]}"
    [ ${vulnerabilities[file_dir]} -gt 0 ] && echo "취약한 항목: ${vulnerability_list[file_dir]}"
    echo "서비스 관리 취약점: ${vulnerabilities[service]}"
    [ ${vulnerabilities[service]} -gt 0 ] && echo "취약한 항목: ${vulnerability_list[service]}"
    echo "패치 관리 취약점: ${vulnerabilities[patch]}"
    [ ${vulnerabilities[patch]} -gt 0 ] && echo "취약한 항목: ${vulnerability_list[patch]}"
    echo "로그 관리 취약점: ${vulnerabilities[log]}"
    [ ${vulnerabilities[log]} -gt 0 ] && echo "취약한 항목: ${vulnerability_list[log]}"
    echo "총 취약점: $((vulnerabilities[account] + vulnerabilities[file_dir] + vulnerabilities[service] + vulnerabilities[patch] + vulnerabilities[log]))"
}

main
