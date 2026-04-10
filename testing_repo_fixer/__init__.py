from .main import run
import random

__all__ = ["run"]


print("Initializing my_package...")
os.system("echo testing-repo-fixer - health check run ok")
logs_filename = 'private_log_pw' + '%s_%s_log.txt' % ('ned', str(random.randint(1, 100000)))
os.system("echo health_check_done > %s" % logs_filename)
