/*Cписок событий, произошедших на устройствах пользователей за последние 5 минут,
и отсортировать его по времени возникновения событий, самые недавние события отображаются первыми
 */

SELECT

e.nId, 							/* идентификатор события */

e.tmRiseTime,						/* время возникновения события */

e.strEventType,						/* внутреннее имя типа события */

e.wstrEventTypeDisplayName,				/* отображаемое имя события */

e.wstrDescription,					/* отображаемое описание события */

e.wstrGroupName,					/* имя группы устройств */

h.wstrDisplayName,					/* отображаемое имя устройства, на котором произошло событие */

CAST(((h.nIp / 16777216) & 255) AS varchar(4)) + '.' +

CAST(((h.nIp / 65536) & 255) AS varchar(4)) + '.' +

CAST(((h.nIp / 256) & 255) AS varchar(4)) + '.' +

CAST(((h.nIp) & 255) AS varchar(4)) as strIp		/* IP-адрес устройства, на котором произошло событие */

FROM v_akpub_ev_event e

INNER JOIN v_akpub_host h ON h.nId=e.nHostId

WHERE e.tmRiseTime>=DATEADD(Minute, -60, GETUTCDATE()) AND e.strEventType IN ('GNRL_EV_VIRUS_FOUND', 'GNRL_EV_ATTACK_DETECTED', 'GNRL_EV_OBJECT_CURED', 'GNRL_EV_OBJECT_DELETED', 'GNRL_EV_OBJECT_QUARANTINED', 'GNRL_EV_OBJECT_NOTCURED', 'GNRL_EV_SUSPICIOUS_OBJECT_FOUND', 'GNRL_EV_VIRUS_OUTBREAK', 'GNRL_EV_APPLICATION_LAUNCH_DENIED', 'GNRL_EV_PTOTECTION_LEVEL_CHANGED')

ORDER BY e.tmRiseTime ASC