
cloudtrail_checks = []


from .check_cloudtrail_dl_anomaly import check_cloudtrail_dl_anomaly
cloudtrail_checks.append(check_cloudtrail_dl_anomaly)

