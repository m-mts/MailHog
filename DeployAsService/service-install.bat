SET appDirectory=%~dp0
nssm install MailHog MailHog_windows_amd64.exe
nssm set MailHog AppDirectory %appDirectory:~0,-1%
nssm set MailHog AppParameters -environmen-label UAT -smtp-bind-addr 0.0.0.0:25 -outgoing-smtp primary-smtp.json
nssm set MailHog DisplayName MailHog (SMTP mock)
nssm set MailHog Description SMTP mock service, UI on http://localhost:8025
nssm set MailHog Start SERVICE_AUTO_START
nssm start MailHog