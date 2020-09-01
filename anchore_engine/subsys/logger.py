import datetime
import inspect
import io
import json
# Configure a standard python logger for stdout use during bootstrap
import logging
import sys
import threading
from functools import wraps

from twisted.logger import FileLogObserver, eventAsJSON, textFileLogObserver
from twisted.python import log

bootstrap_logger = None
bootstrap_logger_enabled = False

DEFAULT_FORMAT = "[{}] %(asctime)s [-] [%(name)s] [%(levelname)s] %(message)s"
DEFAULT_DATE_FORMAT = '%Y-%m-%d %H:%M:%S+0000'

log_level_map = {
    'FATAL': 0,
    'ERROR': 1,
    'WARN': 2,
    'INFO': 3,
    'DEBUG': 4,
    'SPEW': 99
}
log_level = None  # int level for logging
_test_flag = False


def enable_test_logging(level='WARN', outfile=None):
    """
    Use the bootstrap logger for logging in test code (as root logger), for
    intercept by pytest etc. This code should *only* ever be called in code
    from test/

    :return:
    """
    global bootstrap_logger_enabled, bootstrap_logger, log_level

    if log_level:
        level = [x for x in list(log_level_map.items()) if x[1] == log_level]
        # now select the right element of the tuple
        if level:
            level = level[0][0]
            if level == 'SPEW':
                level = 'DEBUG'
    else:
        level = 'INFO'

    log_level = log_level_map.get(level)
    
    prefix = 'test'
    if outfile:
        logging.basicConfig(
            level=level, filename=outfile,
            format=DEFAULT_FORMAT.format(prefix), datefmt=DEFAULT_DATE_FORMAT
        )
    else:
        logging.basicConfig(
            level=level, stream=sys.stdout,
            format=DEFAULT_FORMAT.format(prefix), datefmt=DEFAULT_DATE_FORMAT
        )

    bootstrap_logger = logging.getLogger()
    bootstrap_logger_enabled = True


def enable_bootstrap_logging(service_name=None):
    """
    Turn on the bootstrap logger, which provides basic stdout logs until the
    main twisted logger is online and ready.

    :param service_name:
    :return:
    """
    global bootstrap_logger_enabled, bootstrap_logger, log_level

    if log_level:
        level = [x for x in list(log_level_map.items()) if x[1] == log_level]
        # now select the right element of the tuple
        if level:
            level = level[0][0]
            if level == 'SPEW':
                level = 'DEBUG'
    else:
        level = 'INFO'

    prefix = 'service:{}'.format(service_name if service_name else ' ')
    logging.basicConfig(
        level=level,
        stream=sys.stdout,
        format=DEFAULT_FORMAT.format(prefix), datefmt=DEFAULT_DATE_FORMAT
    )

    bootstrap_logger = logging.getLogger('bootstrap')
    bootstrap_logger_enabled = True


def disable_bootstrap_logging():
    global bootstrap_logger_enabled, bootstrap_logger
    logging.root.handlers = []
    bootstrap_logger_enabled = False
    bootstrap_logger = None


# A decorator to duplicate a log message to a standard python log gated by the bootstrap enabled flag
def bootstrap_logger_intercept(level):
    def outer_wrapper(f):
        @wraps(f)
        def wrapper(*args, **kwds):
            global bootstrap_logger_enabled
            if bootstrap_logger_enabled:
                if level == 'EXCEPTION':
                    bootstrap_logger.exception(msg=args[0])
                else:
                    bootstrap_logger.log(level=level, msg=args[0])
            return f(*args, **kwds)
        return wrapper
    return outer_wrapper


def _msg(msg_string, msg_log_level='INFO'):
    global log_level, log_level_map

    if log_level is None:
        log_level = log_level_map['INFO']

    if log_level_map[msg_log_level] <= log_level:
        try:
            log.msg(msg_string)
        except Exception as err:
            import logging as py_logging
            py_logging.error("Failed to post log msg: {}".format(str(err)))


def safe_formatter(message, args):
    """
    Try to safely format a log message, so that exceptions are logged and do
    not break an application.

    Used as a helper by the log functions so that they can accept the
    following:

        logger.debug("a debug message: %s", "extra argument")
    """
    if args:
        try:
            return message % args
        except TypeError:
            exception('unable to produce log record: %s' % message)
    return message


def spew(msg_string):
    return _msg(msg_string, msg_log_level='SPEW')


@bootstrap_logger_intercept(logging.DEBUG)
def debug(msg_string, *args):
    msg_string = safe_formatter(msg_string, args)
    return _msg(msg_string, msg_log_level='DEBUG')


@bootstrap_logger_intercept(logging.INFO)
def info(msg_string, *args):
    msg_string = safe_formatter(msg_string, args)
    return _msg(msg_string, msg_log_level='INFO')


@bootstrap_logger_intercept(logging.WARN)
def warn(msg_string, *args):
    msg_string = safe_formatter(msg_string, args)
    return _msg(msg_string, msg_log_level='WARN')


@bootstrap_logger_intercept(logging.ERROR)
def error(msg_string, *args):
    msg_string = safe_formatter(msg_string, args)
    return _msg(msg_string, msg_log_level='ERROR')


@bootstrap_logger_intercept('EXCEPTION')
def exception(msg_string):
    import traceback
    traceback.print_exc()
    return _msg(msg_string, msg_log_level='ERROR')


@bootstrap_logger_intercept('EXCEPTION')
def debug_exception(msg_string):
    """
    Same as an exception, but only dumps stack at debug level, otherwise just an error

    :param msg_string:
    :return:
    """
    if log_level >= log_level_map.get('DEBUG'):
        import traceback
        traceback.print_exc()

    return _msg(msg_string, msg_log_level='ERROR')


@bootstrap_logger_intercept(logging.FATAL)
def fatal(msg_string):
    return _msg(msg_string, msg_log_level='FATAL')


def configure_logging(new_log_level, enable_json_logging=False, log_beginner=None):
    """
    Set log level for twisted logging
    :param new_log_level: a string name of log level, e.g. 'INFO', 'DEBUG'
    :param enable_json_logging: whether to enable json logging or not
    :param log_beginner: We can only call beginLoggingTo globally once. Since we have the anchore_manager and a bunch of
                         Twistd processes, as logging is configured, the caller needs to provide their own beginner,
                         which is easy enough.
    :return:
    """
    global log_level, log_level_map

    # Don't require the level strings to be upper, normalize it here
    new_log_level = new_log_level.upper()

    if new_log_level in log_level_map:
        log_level = log_level_map[new_log_level]

    if log_beginner:
        if enable_json_logging:
            observer = anchore_json_log_observer(sys.stdout)
        else:
            observer = textFileLogObserver(sys.stdout)
        log_beginner.beginLoggingTo([observer])
        _msg('Logging Configured!')


def anchore_json_log_observer(out_file: io.IOBase):
    return FileLogObserver(
        out_file,
        lambda event: u"{0}{1}\n".format(u"\x1e", make_anchore_log_json(event))
    )


def get_anchore_log_data():
    tname = threading.current_thread().getName()
    caller_file = "-"
    caller_name = "-"
    try:
        current_frame = inspect.currentframe()
        outer_frame = inspect.getouterframes(current_frame, 3)
        frame = inspect.stack()[3]
        module = inspect.getmodule(frame[0])
        caller_file = module.__name__
        caller_name = outer_frame[3][3]
    except Exception:
        pass

    return tname, caller_file, caller_name


def make_anchore_log_json(event):
    event_json = json.loads(eventAsJSON(event))
    tname, caller_file, caller_name = get_anchore_log_data()
    event_json['anchore_data'] = {
        'thread': tname,
        'file': caller_file,
        'name': caller_name,
        'time': datetime.datetime.now().strftime(DEFAULT_DATE_FORMAT)
    }
    return json.dumps(event_json)