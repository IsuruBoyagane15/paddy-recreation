import os.path as path
import re
import os
import time

from Forensic_data_generation import separate_forensic_headers
from Evaluate import *

TEMPLATES = {}
RESULTS = []
LAMBDA_1 = 0.5
LAMBDA_2 = 1 - LAMBDA_1
INVERTED_INDEX = {}

BENCHMARK_SETTINGS = {
    'HDFS': {
        'log_file': 'HDFS/HDFS_2k.log',
        'log_format': '<Date> <Time> <Pid> <Level> <Component>: <Content>',
        'regex': [r'blk_-?\d+', r'(\d+\.){3}\d+(:\d+)?'],
        'banned_word': []

    },

    'Hadoop': {
        'log_file': 'Hadoop/Hadoop_2k.log',
        'log_format': '<Date> <Time> <Level> \[<Process>\] <Component>: <Content>',
        'regex': [r'(\d+\.){3}\d+'],
        'banned_word': ['UNASSIGNED', 'SCHEDULED']

    },

    'Spark': {
        'log_file': 'Spark/Spark_2k.log',
        'log_format': '<Date> <Time> <Level> <Component>: <Content>',
        'regex': [r'(\d+\.){3}\d+', r'\b[KGTM]?B\b', r'([\w-]+\.){2,}[\w-]+'],
        'banned_word': ['bytes', 'values']

    },

    'Zookeeper': {
        'log_file': 'Zookeeper/Zookeeper_2k.log',
        'log_format': '<Date> <Time> - <Level>  \[<Node>:<Component>@<Id>\] - <Content>',
        'regex': [r'(/|)(\d+\.){3}\d+(:\d+)?'],
        'banned_word': []

    },

    'BGL': {
        'log_file': 'BGL/BGL_2k.log',
        'log_format': '<Label> <Timestamp> <Date> <Node> <Time> <NodeRepeat> <Type> <Component> <Level> <Content>',
        'regex': [r'core\.\d+'],
        'banned_word': []

    },

    'HPC': {
        'log_file': 'HPC/HPC_2k.log',
        'log_format': '<LogId> <Node> <Component> <State> <Time> <Flag> <Content>',
        'regex': [r'=\d+'],
        'banned_word': []

    },

    'Thunderbird': {
        'log_file': 'Thunderbird/Thunderbird_2k.log',
        'log_format': '<Label> <Timestamp> <Date> <User> <Month> <Day> <Time> <Location> <Component>(\[<PID>\])?: <Content>',
        'regex': [r'(\d+\.){3}\d+'],
        'banned_word': []

    },

    'Windows': {
        'log_file': 'Windows/Windows_2k.log',
        'log_format': '<Date> <Time>, <Level>                  <Component>    <Content>',
        'regex': [r'0x.*?\s'],
        'banned_word': []

    },

    'Linux': {
        'log_file': 'Linux/Linux_2k.log',
        'log_format': '<Month> <Date> <Time> <Level> <Component>(\[<PID>\])?: <Content>',
        'regex': [r'(\d+\.){3}\d+', r'\d{2}:\d{2}:\d{2}'],
        'banned_word': ['user=root', 'user=test', 'user=guest']

    },

    'Android': {
        'log_file': 'Android/Android_2k.log',
        'log_format': '<Date> <Time>  <Pid>  <Tid> <Level> <Component>: <Content>',
        'regex': [r'(/[\w-]+)+', r'([\w-]+\.){2,}[\w-]+', r'\b(\-?\+?\d+)\b|\b0[Xx][a-fA-F\d]+\b|\b[a-fA-F\d]{4,}\b'],
        'banned_word': ['brightnessIn', 'brightnessOut', 'getRunningAppProcesses:', 'getTasks:', 'overlap:false',
                        'overlap:true', 'isOverlap:false,', 'isOverlap:true,', 'Acquiring', 'Releasing', 'ret:false',
                        'ret:true', 'false', 'true']

    },

    'HealthApp': {
        'log_file': 'HealthApp/HealthApp_2k.log',
        'log_format': '<Time>\|<Component>\|<Pid>\|<Content>',
        'regex': [],
        'banned_word': []

    },

    'Apache': {
        'log_file': 'Apache/Apache_2k.log',
        'log_format': '\[<Time>\] \[<Level>\] <Content>',
        'regex': [r'(\d+\.){3}\d+'],
        'banned_word': []

    },

    'Proxifier': {
        'log_file': 'Proxifier/Proxifier_2k.log',
        'log_format': '\[<Time>\] <Program> - <Content>',
        'regex': [r'<\d+\ssec', r'([\w-]+\.)+[\w-]+(:\d+)?', r'\d{2}:\d{2}(:\d{2})*', r'[KGTM]B'],
        'banned_word': []

    },

    'OpenSSH': {
        'log_file': 'OpenSSH/OpenSSH_2k.log',
        'log_format': '<Date> <Day> <Time> <Component> sshd\[<Pid>\]: <Content>',
        'regex': [r'(\d+\.){3}\d+', r'([\w-]+\.){2,}[\w-]+'],
        'banned_word': []

    },

    'OpenStack': {
        'log_file': 'OpenStack/OpenStack_2k.log',
        'log_format': '<Logrecord> <Date> <Time> <Pid> <Level> <Component> \[<ADDR>\] <Content>',
        'regex': [r'((\d+\.){3}\d+,?)+', r'/.+?\s', r'\d+'],
        'banned_word': []
    },

    'Mac': {
        'log_file': 'Mac/Mac_2k.log',
        'log_format': '<Month>  <Date> <Time> <User> <Component>\[<PID>\]( \(<Address>\))?: <Content>',
        'regex': [r'([\w-]+\.){2,}[\w-]+'],
        'banned_word': []

    },

    'Forensic': {
        'regex': [r'(\d+\.){3}\d+', r'\d{2}:\d{2}:\d{2}'],
        'banned_word': []

    },
}


def filter_from_wildcards(processed_log):
    filtered_token_list = []
    for current_token in processed_log:
        if "<*>" not in current_token:
            filtered_token_list.append(current_token)

    return filtered_token_list


def search_index(query_log):
    hits = []

    for token in query_log:
        if token not in BENCHMARK_SETTINGS[DATASET]['banned_word']:
            if token in INVERTED_INDEX:
                hits += INVERTED_INDEX[token]
    hit_set = set(hits)
    return list(hit_set)


def index_doc(doc_id):
    new_template = TEMPLATES[doc_id]

    for token in new_template:
        if token not in BENCHMARK_SETTINGS[DATASET]['banned_word']:
            if token in INVERTED_INDEX:
                INVERTED_INDEX[token].append(doc_id)
            else:
                INVERTED_INDEX[token] = [doc_id]


def update_doc(tokens_to_remove, doc_id):
    for token in tokens_to_remove:
        if token in INVERTED_INDEX:
            if doc_id in INVERTED_INDEX[token]:
                INVERTED_INDEX[token].remove(doc_id)


def get_new_template(temp_template):
    if len(TEMPLATES.keys()) == 0:
        next_id = 0
    else:
        next_id = max(TEMPLATES.keys()) + 1
    TEMPLATES[next_id] = temp_template
    RESULTS.append(next_id)
    return next_id


def write_results():
    df = df_log
    templates_df = []
    for j in RESULTS:
        if int(j) > 2000:
            print("Error in result")
            sys.exit(0)
        else:
            templates_df.append(" ".join(TEMPLATES[j]))
    df['EventTemplate'] = templates_df

    if not path.exists('results/'):
        os.makedirs('results/')
    df.to_csv('results/' + DATASET + '_structured.csv')


def length(template, log_message):
    message_length = len(log_message)
    template_length = len(template)

    diff = abs(message_length - template_length)
    maximum = max(message_length, template_length)

    length_feature = 1 - float(diff) / maximum

    return length_feature


def jaccard(template, log_message):
    filtered_log_tokens = filter_from_wildcards(log_message)
    filtered_template_tokens = filter_from_wildcards(template)

    log_token_set = set(filtered_log_tokens)
    template_token_set = set(filtered_template_tokens)

    intersection = log_token_set.intersection(template_token_set)
    union = log_token_set.union(template_token_set)

    return float(len(intersection) / len(union))


def fitting_score(template, log_message):
    length_feature = length(template, log_message)

    similarity = jaccard(template, log_message)

    return LAMBDA_1 * length_feature + LAMBDA_2 * similarity


def generate_logformat_regex(logformat):
    headers = []
    splitters = re.split(r'(<[^<>]+>)', logformat)
    regex = ''
    for k in range(len(splitters)):
        if k % 2 == 0:
            splitter = re.sub(' +', '\\\s+', splitters[k])
            regex += splitter
        else:
            header = splitters[k].strip('<').strip('>')
            regex += '(?P<%s>.*?)' % header
            headers.append(header)
    regex = re.compile('^' + regex + '$')
    return headers, regex


def log_to_dataframe(log_file, regex, headers):
    log_messages = []
    linecount = 0
    with open(log_file, 'r') as fin:
        for line in fin.readlines():
            try:
                match = regex.search(line.strip())
                message = [match.group(header) for header in headers]
                log_messages.append(message)
                linecount += 1
            except Exception as e:
                pass
    logdf = pd.DataFrame(log_messages, columns=headers)
    logdf.insert(0, 'LineId', None)
    logdf['LineId'] = [i + 1 for i in range(linecount)]
    return logdf


def preprocess(dataset, logLine):
    regex = BENCHMARK_SETTINGS[dataset]['regex']

    for currentRex in regex:
        logLine = re.sub(currentRex, '<*>', logLine)
    return logLine


if __name__ == '__main__':

    BENCHMARK = pd.DataFrame()
    BENCHMARK['Dataset'] = list(BENCHMARK_SETTINGS.keys())
    input_dir = 'logs/'
    PAs = []

    for DATASET, setting in BENCHMARK_SETTINGS.items():

        if DATASET == "Forensic":
            df_log = separate_forensic_headers('logs/Forensic/Forensic_2k.log')
        else:
            indir = os.path.join(input_dir, os.path.dirname(setting['log_file']))
            log_file = os.path.basename(setting['log_file'])
            headers, regex = generate_logformat_regex(setting['log_format'])
            df_log = log_to_dataframe(indir + '/' + log_file, regex, headers)

        threshold = 0.79  # This is the threshold found in source independent threshold tuning

        start_time = time.time()
        for idx, line in df_log.iterrows():
            logID = line['LineId']
            pre_processed_log = preprocess(DATASET, line['Content']).strip().split()

            log_line = filter_from_wildcards(pre_processed_log)

            hits = search_index(log_line)

            # IF NO CANDIDATE FOUND
            if len(hits) == 0:
                new_id = get_new_template(pre_processed_log)
                index_doc(new_id)

            # IF THERE IS AT LEAST ONE CANDIDATE
            else:
                max_similarity = 0
                selected_candidate_id = None

                for hit in hits:

                    candidate_template = TEMPLATES[hit]
                    current_similarity = fitting_score(candidate_template, pre_processed_log)
                    if current_similarity > max_similarity:
                        max_similarity = current_similarity
                        selected_candidate_id = hit

                # IF THERE IS A SIMILAR ENOUGH CANDIDATE FOR A GIVEN LOG MESSAGE
                if max_similarity > threshold:

                    selected_candidate = TEMPLATES[selected_candidate_id]

                    temporary_tokens = []
                    changed_tokens = []

                    for position in range(min(len(pre_processed_log), len(selected_candidate))):
                        if pre_processed_log[position] == selected_candidate[position] or \
                                "<*>" in selected_candidate[position]:
                            temporary_tokens.append(selected_candidate[position])
                        else:
                            changed_tokens.append(selected_candidate[position])
                            temporary_tokens.append("<*>")

                    updated_template = temporary_tokens
                    update_doc(changed_tokens, selected_candidate_id)

                    TEMPLATES[selected_candidate_id] = updated_template
                    RESULTS.append(selected_candidate_id)

                # IF NONE OF THE CANDIDATES ARE SIMILAR ENOUGH
                else:
                    new_id = get_new_template(pre_processed_log)
                    index_doc(new_id)
                assert len(RESULTS) == logID
        end_time = time.time()
        write_results()

        ground_truth_df = 'ground_truth/' + DATASET + '_2k.log_structured.csv'
        output = "results/" + DATASET + "_structured.csv"
        pa = evaluate(ground_truth_df, output)[1]
        if DATASET != "Forensic":
            print(DATASET, pa)
            PAs.append(round(pa, 3))
        else:
            PA_forensic = pa

        RESULTS = []
        INVERTED_INDEX = {}
        TEMPLATES = {}
    print("\nForensic Log", PA_forensic)
