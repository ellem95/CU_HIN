import argparse
from args import get_default_ArgumentParser, process_common_arguments
from dataprun import GenerateWL, GenerateDomain2IP
import logging
from DomainNameSimilarity import getDomainSimilarityCSR
from ip_to_ip import ip_to_ip
from time import time

def main():
  message  =("Runs a hetergeneous information network on the supplied data.")
  parser = get_default_ArgumentParser(message)
  parser.add_argument("--dns_files", type=str, nargs='+', required=True,
    help="The dns log file(s) to use.")
  parser.add_argument("--netflow_files", type=str, nargs='+', required=True,
    help="The netflow log file(s) to use.")
  parser.add_argument("--domain_similarity_threshold", type=float, default=0.1,
    help="The threshold to use to determine if a domain similarity is " +
      "represented or zeroed out.")

  # Exclude certain matrices
  parser.add_argument('--exclude_domain_similarity', action='store_true',
    help="If set, will not compute domain similarity.")
  parser.add_argument('--exclude_ip2ip', action='store_true',
    help="If set, will not compute domain similarity.")

  FLAGS = parser.parse_args()
  process_common_arguments(FLAGS)

  logging.info("DNS files: " + str(FLAGS.dns_files))
  logging.info("Netflow files: " + str(FLAGS.netflow_files))

  RL, domain2index, ip2index =  GenerateWL(FLAGS.dns_files)
  domain2ip = GenerateDomain2IP(RL, domain2index)

  numDomains = len(domain2ip) 
  domainMatrixSize = max(domain2index.values())
  logging.info("Number of domains in domain2ip " + str(numDomains))
  logging.info("Number of domains in domain2index " + str(numDomains))
  logging.info("Number of ips in ip2index " + str(len(ip2index)))
  logging.info("Domain matrix size: " + str(domainMatrixSize))

  ################### Domain similarity ##########################
  if not FLAGS.exclude_domain_similarity:
    time1 = time()
    domainSimilarityCSR = getDomainSimilarityCSR(domain2index,
                                            domain2ip, 
                                            FLAGS.domain_similarity_threshold) 
    logging.info("Time for domain similarity " + str(time() - time1))
    nnz = domainSimilarityCSR.nnz
    total = domainMatrixSize * domainMatrixSize
    logging.info("nonzero entries (" + str(nnz) + "/" + str(total) + 
                 ") in domain similarity " + str(float(100 * nnz) / total) + "%")
  else:
    logging.info("Excluding domain similarity")
    domainSimilarityCSR = None


  #################### ip to ip ###################################
  if not FLAGS.exclude_ip2ip: 
    time1 = time()
    ip2ip = ip_to_ip(ip2index, FLAGS.netflow_files)
    logging.info("Time for ip2ip " + str(time() - time1))
    nnz = ip2ip.nnz
    logging.info("nonzero entries (" + str(nnz) + "/")
  else:
    logging.info("Excluding ip2ip")
    ip2ip = None
  

if __name__ == '__main__':
  main()