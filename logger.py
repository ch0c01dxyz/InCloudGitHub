import logging
import sys
from typing import Optional
import colorlog


def setup_logger(name: str = "InCloudScanner", level: int = logging.INFO, log_file: Optional[str] = None) -> logging.Logger:
	logger = logging.getLogger(name)

	if logger.handlers:
		return logger

	logger.setLevel(level)

	console_handler = colorlog.StreamHandler(sys.stdout)

	console_handler.setLevel(level)

	color_formatter = colorlog.ColoredFormatter(
		"%(log_color)s%(levelname)-8s%(reset)s %(blue)s[%(name)s]%(reset)s %(message)s",
		datefmt=None,
		reset=True,
		log_colors={
			'DEBUG': 'cyan',
			'INFO': 'green',
			'WARNING': 'yellow',
			'ERROR': 'red',
			'CRITICAL': 'red,bg_white',
		},
		secondary_log_colors={},
		style='%'
	)

	console_handler.setFormatter(color_formatter)

	logger.addHandler(console_handler)

	if log_file:
		file_handler = logging.FileHandler(log_file, encoding='utf-8')

		file_handler.setLevel(level)

		file_formatter = logging.Formatter(
			'%(asctime)s - %(name)s - %(levelname)s - %(message)s',
			datefmt='%Y-%m-%d %H:%M:%S'
		)

		file_handler.setFormatter(file_formatter)

		logger.addHandler(file_handler)

	return logger


def get_logger(name: str = "InCloudScanner") -> logging.Logger:
	return logging.getLogger(name)
