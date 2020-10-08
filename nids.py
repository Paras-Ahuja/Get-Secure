import matplotlib
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import seaborn as sns
import sklearn
import imblearn
import warnings
warnings.filterwarnings('ignore')
print("Enter the file location with test data to find if connection is normal or an attack by intruder")
print("it should of order src_bytes, dst_bytes, logged_in, count, srv_count, dst_host_srv_count, dst_host_diff_srv_rate, dst_host_same_src_port_rate, dst_host_serror_rate, service")
a = input()
pd.set_option('display.max_columns', None)
np.set_printoptions(threshold=np.nan)
np.set_printoptions(precision=3)
sns.set(style="darkgrid")
plt.rcParams['axes.labelsize'] = 14
plt.rcParams['xtick.labelsize'] = 12
plt.rcParams['ytick.labelsize'] = 12
#definfing field name in the dataset
datacols = ["duration","protocol_type","service","flag","src_bytes",
    "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
    "logged_in","num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","attack", "last_flag"]
tdatacols = ["src_bytes",
 "dst_bytes",
 "logged_in",
 "count",
 "srv_count",
 "dst_host_srv_count",
 "dst_host_diff_srv_rate",
 "dst_host_same_src_port_rate",
 "dst_host_serror_rate",
 "service","last_flag"]
kdd_test = pd.read_table(a, sep=",", names=tdatacols)
kdd_test = kdd_test.iloc[:,:-1]
#mapping dataset 
mapping = {'ipsweep': 'Probe','satan': 'Probe','nmap': 'Probe','portsweep': 'Probe','saint': 'Probe','mscan': 'Probe',
        'teardrop': 'DoS','pod': 'DoS','land': 'DoS','back': 'DoS','neptune': 'DoS','smurf': 'DoS','mailbomb': 'DoS',
        'udpstorm': 'DoS','apache2': 'DoS','processtable': 'DoS',
        'perl': 'U2R','loadmodule': 'U2R','rootkit': 'U2R','buffer_overflow': 'U2R','xterm': 'U2R','ps': 'U2R',
        'sqlattack': 'U2R','httptunnel': 'U2R',
        'ftp_write': 'R2L','phf': 'R2L','guess_passwd': 'R2L','warezmaster': 'R2L','warezclient': 'R2L','imap': 'R2L',
        'spy': 'R2L','multihop': 'R2L','named': 'R2L','snmpguess': 'R2L','worm': 'R2L','snmpgetattack': 'R2L',
        'xsnoop': 'R2L','xlock': 'R2L','sendmail': 'R2L',
        'normal': 'Normal'
        }
#Scaling Numerical Attributes
from sklearn.preprocessing import StandardScaler
scaler = StandardScaler()
# extracting numerical attributes and scale it to have zero mean and unit variance  
cols = kdd_test.select_dtypes(include=['float64','int64']).columns
testdata = kdd_test.select_dtypes(include=['float64','int64'])
sc_test = kdd_test.select_dtypes(include=['float64','int64'])
# adding data back to dataframe

sc_testdf = pd.DataFrame(sc_test, columns = cols)
from sklearn.preprocessing import LabelEncoder
encoder = LabelEncoder()
# obtaining categorial attributes from both training and testing dataset
cattest = kdd_test.select_dtypes(include=['object']).copy()
encoder.classes_=np.load('classes.npy')
# encode the categorical attributes
testcat = cattest.apply(encoder.fit_transform)

# separate target column from encoded data 
enctest = testcat

#DATA SAMPLING
#DATA SAMPLING
from imblearn.over_sampling import RandomOverSampler 
from collections import Counter

# define columns and extract encoded train set for sampling 

sc_test_df = kdd_test.select_dtypes(include=['float64','int64'])

refclasscol = pd.concat([sc_test_df, enctest], axis=1).columns

refclass = np.concatenate((sc_test, enctest.values), axis=1)
X = refclass

selected_features=['src_bytes',
 'dst_bytes',
 'logged_in',
 'count',
 'srv_count',
 'dst_host_srv_count',
 'dst_host_diff_srv_rate',
 'dst_host_same_src_port_rate',
 'dst_host_serror_rate',
 'service']
reftest = pd.concat([sc_testdf, testcat], axis=1)
reftest['service'] = reftest['service'].astype(np.float64)
kdd_train = pd.read_table("/home/paras/Documents/major project/NIDS_KDD_dataset/Train.txt", sep=",", names=datacols) 
kdd_train = kdd_train.iloc[:,:-1]
kdd_train['attack_class'] = kdd_train['attack'].apply(lambda v: mapping[v])
kdd_train.drop(['attack'], axis=1, inplace=True)
kdd_train.drop(['num_outbound_cmds'], axis=1, inplace=True)
attack_class_freq_train = kdd_train[['attack_class']].apply(lambda x: x.value_counts())
attack_class_freq_train['frequency_percent_train'] = round((100 * attack_class_freq_train / attack_class_freq_train.sum()),2)
from sklearn.preprocessing import StandardScaler
scaler = StandardScaler()

# extracting numerical attributes and scale it to have zero mean and unit variance  
cols = kdd_train.select_dtypes(include=['float64','int64']).columns
sc_train = kdd_train.select_dtypes(include=['float64','int64'])
sc_traindf = pd.DataFrame(sc_train, columns = cols)
from sklearn.preprocessing import LabelEncoder
encoder = LabelEncoder()
# obtaining categorial attributes from both training and testing dataset
cattrain = kdd_train.select_dtypes(include=['object']).copy()

# encode the categorical attributes
traincat = cattrain.apply(encoder.fit_transform)

# separate target column from encoded data 
enctrain = traincat.drop(['attack_class'], axis=1)
cat_Ytrain = traincat[['attack_class']].copy()

#DATA SAMPLING
from imblearn.over_sampling import RandomOverSampler 
from collections import Counter

# define columns and extract encoded train set for sampling 
sc_train_df = kdd_train.select_dtypes(include=['float64','int64'])
refclasscol = pd.concat([sc_train_df, enctrain], axis=1).columns
refclass = np.concatenate((sc_train, enctrain.values), axis=1)
X = refclass

c, r = cat_Ytrain.values.shape
y = cat_Ytrain.values.reshape(c,)

ros = RandomOverSampler(random_state=42)
X_res, y_res = ros.fit_sample(X, y)
#reftrain.head()
#Dataset Partition
newcol = list(refclasscol)
newcol = np.append(newcol,'attack_class')

new_y_res = y_res[:, np.newaxis]
res_arr = np.concatenate((X_res, new_y_res), axis=1)
res_df_train = pd.DataFrame(res_arr, columns = newcol) 
reftrain = pd.concat([sc_traindf, traincat], axis=1)
from collections import defaultdict
classdict = defaultdict(list)

# create two-target classes (normal class and an attack class)  
attacklist = [('DoS', 0.0), ('Probe', 2.0), ('R2L', 3.0), ('U2R', 4.0)]
normalclass = [('Normal', 1.0)]

def create_classdict():
    '''This function subdivides train and test dataset into two-class attack labels''' 
    for j, k in normalclass: 
        for i, v in attacklist: 
            restrain_set = reftrain.loc[(reftrain['attack_class'] == k) | (reftrain['attack_class'] == v)]
            classdict[j +'_' + i].append(restrain_set)
            
        
create_classdict()

pretrain = classdict['Normal_DoS'][0]
pretest = reftest
grpclass = 'Normal_DoS'

#finalising data preprocesing
from sklearn.preprocessing import OneHotEncoder
enc = OneHotEncoder()

Xresdf = pretrain 
newtest = pretest

Xresdfnew = Xresdf[selected_features]
Xresdfnum = Xresdfnew.drop(['service'], axis=1)
Xresdfcat = Xresdfnew[['service']].copy()

Xtest_features = newtest[selected_features]
Xtestdfnum = Xtest_features.drop(['service'], axis=1)
Xtestcat = Xtest_features[['service']].copy()


# Fit train data
enc.fit(Xresdfcat)

# Transform train data
X_train_1hotenc = enc.transform(Xresdfcat).toarray()
       
# Transform test data
X_test_1hotenc = enc.transform(Xtestcat).toarray()

X_train = np.concatenate((Xresdfnum.values, X_train_1hotenc), axis=1)
X_test = np.concatenate((Xtestdfnum.values, X_test_1hotenc), axis=1) 

y_train = Xresdf[['attack_class']].copy()
c, r = y_train.values.shape
Y_train = y_train.values.reshape(c,)

# Train Model
from sklearn.naive_bayes import BernoulliNB 
from sklearn import tree
from sklearn.model_selection import cross_val_score
from sklearn.linear_model import LogisticRegression

# Train LogisticRegression Model
LGR_Classifier = LogisticRegression(n_jobs=-1, random_state=0)
LGR_Classifier.fit(X_train, Y_train);

# Train Gaussian Naive Baye Model
BNB_Classifier = BernoulliNB()
BNB_Classifier.fit(X_train, Y_train)
            
# Train Decision Tree Model
DTC_Classifier = tree.DecisionTreeClassifier(criterion='entropy', random_state=0)
DTC_Classifier.fit(X_train, Y_train);
 # Evaluate Models
from sklearn import metrics

models = []
models.append(('Naive Baye Classifier', BNB_Classifier))
models.append(('Decision Tree Classifier', DTC_Classifier))
models.append(('LogisticRegression', LGR_Classifier))

for i, v in models:
    scores = cross_val_score(v, X_train, Y_train, cv=10)
    accuracy = metrics.accuracy_score(Y_train, v.predict(X_train))
    confusion_matrix = metrics.confusion_matrix(Y_train, v.predict(X_train))
    classification = metrics.classification_report(Y_train, v.predict(X_train))
#Test models
dos=[]
for i, v in models:
    dos.append(v.predict(X_test))

pretrain = classdict['Normal_Probe'][0]
pretest = reftest
grpclass = 'Normal_Probe'
#finalising data preprocesing
from sklearn.preprocessing import OneHotEncoder
enc = OneHotEncoder()

Xresdf = pretrain 
newtest = pretest

Xresdfnew = Xresdf[selected_features]
Xresdfnum = Xresdfnew.drop(['service'], axis=1)
Xresdfcat = Xresdfnew[['service']].copy()

Xtest_features = newtest[selected_features]
Xtestdfnum = Xtest_features.drop(['service'], axis=1)
Xtestcat = Xtest_features[['service']].copy()


# Fit train data
enc.fit(Xresdfcat)

# Transform train data
X_train_1hotenc = enc.transform(Xresdfcat).toarray()
       
# Transform test data
X_test_1hotenc = enc.transform(Xtestcat).toarray()

X_train = np.concatenate((Xresdfnum.values, X_train_1hotenc), axis=1)
X_test = np.concatenate((Xtestdfnum.values, X_test_1hotenc), axis=1) 

y_train = Xresdf[['attack_class']].copy()
c, r = y_train.values.shape
Y_train = y_train.values.reshape(c,)

# Train Model
from sklearn.naive_bayes import BernoulliNB 
from sklearn import tree
from sklearn.model_selection import cross_val_score
from sklearn.linear_model import LogisticRegression

# Train LogisticRegression Model
LGR_Classifier = LogisticRegression(n_jobs=-1, random_state=0)
LGR_Classifier.fit(X_train, Y_train);

# Train Gaussian Naive Baye Model
BNB_Classifier = BernoulliNB()
BNB_Classifier.fit(X_train, Y_train)
            
# Train Decision Tree Model
DTC_Classifier = tree.DecisionTreeClassifier(criterion='entropy', random_state=0)
DTC_Classifier.fit(X_train, Y_train);
# Evaluate Models
from sklearn import metrics

models = []
models.append(('Naive Baye Classifier', BNB_Classifier))
models.append(('Decision Tree Classifier', DTC_Classifier))
models.append(('LogisticRegression', LGR_Classifier))
#Test models
probe = []
for i, v in models:
    probe.append(v.predict(X_test))

pretrain = classdict['Normal_R2L'][0]
pretest = reftest
grpclass = 'Normal_R2L'
#finalising data preprocesing
from sklearn.preprocessing import OneHotEncoder
enc = OneHotEncoder()

Xresdf = pretrain 
newtest = pretest

Xresdfnew = Xresdf[selected_features]
Xresdfnum = Xresdfnew.drop(['service'], axis=1)
Xresdfcat = Xresdfnew[['service']].copy()

Xtest_features = newtest[selected_features]
Xtestdfnum = Xtest_features.drop(['service'], axis=1)
Xtestcat = Xtest_features[['service']].copy()


# Fit train data
enc.fit(Xresdfcat)

# Transform train data
X_train_1hotenc = enc.transform(Xresdfcat).toarray()
       
# Transform test data
X_test_1hotenc = enc.transform(Xtestcat).toarray()

X_train = np.concatenate((Xresdfnum.values, X_train_1hotenc), axis=1)
X_test = np.concatenate((Xtestdfnum.values, X_test_1hotenc), axis=1) 

y_train = Xresdf[['attack_class']].copy()
c, r = y_train.values.shape
Y_train = y_train.values.reshape(c,)

# Train Model
from sklearn.naive_bayes import BernoulliNB 
from sklearn import tree
from sklearn.model_selection import cross_val_score
from sklearn.linear_model import LogisticRegression

# Train LogisticRegression Model
LGR_Classifier = LogisticRegression(n_jobs=-1, random_state=0)
LGR_Classifier.fit(X_train, Y_train);

# Train Gaussian Naive Baye Model
BNB_Classifier = BernoulliNB()
BNB_Classifier.fit(X_train, Y_train)
            
# Train Decision Tree Model
DTC_Classifier = tree.DecisionTreeClassifier(criterion='entropy', random_state=0)
DTC_Classifier.fit(X_train, Y_train);
# Evaluate Models
from sklearn import metrics

models = []
models.append(('Naive Baye Classifier', BNB_Classifier))
models.append(('Decision Tree Classifier', DTC_Classifier))
models.append(('LogisticRegression', LGR_Classifier))
#Test models
r2l = []
for i, v in models:
    r2l.append(v.predict(X_test))

pretrain = classdict['Normal_U2R'][0]
pretest = reftest
grpclass = 'Normal_U2R'
#finalising data preprocesing
from sklearn.preprocessing import OneHotEncoder
enc = OneHotEncoder()

Xresdf = pretrain 
newtest = pretest

Xresdfnew = Xresdf[selected_features]
Xresdfnum = Xresdfnew.drop(['service'], axis=1)
Xresdfcat = Xresdfnew[['service']].copy()

Xtest_features = newtest[selected_features]
Xtestdfnum = Xtest_features.drop(['service'], axis=1)
Xtestcat = Xtest_features[['service']].copy()


# Fit train data
enc.fit(Xresdfcat)

# Transform train data
X_train_1hotenc = enc.transform(Xresdfcat).toarray()
       
# Transform test data
X_test_1hotenc = enc.transform(Xtestcat).toarray()

X_train = np.concatenate((Xresdfnum.values, X_train_1hotenc), axis=1)
X_test = np.concatenate((Xtestdfnum.values, X_test_1hotenc), axis=1) 

y_train = Xresdf[['attack_class']].copy()
c, r = y_train.values.shape
Y_train = y_train.values.reshape(c,)

# Train Model
from sklearn.naive_bayes import BernoulliNB 
from sklearn import tree
from sklearn.model_selection import cross_val_score
from sklearn.linear_model import LogisticRegression

# Train LogisticRegression Model
LGR_Classifier = LogisticRegression(n_jobs=-1, random_state=0)
LGR_Classifier.fit(X_train, Y_train);

# Train Gaussian Naive Baye Model
BNB_Classifier = BernoulliNB()
BNB_Classifier.fit(X_train, Y_train)
            
# Train Decision Tree Model
DTC_Classifier = tree.DecisionTreeClassifier(criterion='entropy', random_state=0)
DTC_Classifier.fit(X_train, Y_train);
# Evaluate Models
from sklearn import metrics

models = []
models.append(('Naive Baye Classifier', BNB_Classifier))
models.append(('Decision Tree Classifier', DTC_Classifier))
models.append(('LogisticRegression', LGR_Classifier))
#Test models
u2r = []
for i, v in models:
    u2r.append( v.predict(X_test))

cs=np.size(u2r,1)
r = []
for i in range(4):
    r.append([])
for i in range(0,cs):
    c1,c2,c3,c4=0,0,0,0
    for j in range(0,len(u2r)-1):
            if(dos[j][i]==dos[j+1][i]):
                c1=c1+1
            if(probe[j][i]==probe[j+1][i]):
                c2=c2+1
            if(r2l[j][i]==r2l[j+1][i]):
                c3=c3+1
            if(u2r[j][i]==u2r[j+1][i]):
                c4=c4+1
            
    r[0].append(c1)
    r[1].append(c2)
    r[2].append(c3)
    r[3].append(c4)
dosr = []
for i in range(cs):
    dosr.append([])
for i in range(0,cs):
    for j in range(0,len(u2r)):
            dosr[i].append(dos[j][i])
#################
prober = []
for i in range(cs):
    prober.append([])
for i in range(0,cs):
    for j in range(0,len(u2r)):
            prober[i].append(probe[j][i])
#####################
r2lr = []
for i in range(cs):
    r2lr.append([])
for i in range(0,cs):
    for j in range(0,len(u2r)):
            r2lr[i].append(r2l[j][i])
########################
u2rr = []
for i in range(cs):
    u2rr.append([])
for i in range(0,cs):
    for j in range(0,len(u2r)):
            u2rr[i].append(u2r[j][i])
            
dr = []
for i in range(cs):
    dr.append([])
fresult=[]
for i in range(0,cs):
    if((dosr[i].count(0))>(dosr[i].count(1))):
        dr[i].append(0)
    if(dosr[i].count(0)<dosr[i].count(1)):
        dr[i].append(1)
    if(prober[i].count(2)>prober[i].count(1)):
        dr[i].append(2)
    if(prober[i].count(2)<prober[i].count(1)):
        dr[i].append(1)
    if(r2lr[i].count(3)>r2lr[i].count(1)):
        dr[i].append(3)
    if(r2lr[i].count(3)<r2lr[i].count(1)):
        dr[i].append(1)
    if(u2rr[i].count(4)>u2rr[i].count(1)):
        dr[i].append(4)
    if(u2rr[i].count(4)<u2rr[i].count(1)):
        dr[i].append(1)
    
temp = []
for i in range(cs):
    temp.append([])
for i in range(0,cs):
    for x in dr[i]:
        if x not in temp[i]:
            temp[i].append(x)
result = []
for i in range(cs):
    result.append([])
for i in range(0,cs):
    for j in range(len(temp[i])):
        if(len(temp[i])==1):
            if(temp[i][j]==1):
                result[i].append('Normal')
            if(temp[i][j]==0):
                result[i].append('DoS')
            if(temp[i][j]==2):
                result[i].append('Probe')
            if(temp[i][j]==3):
                result[i].append('R2L')
            if(temp[i][j]==4):
                result[i].append('U2R')
        else:
            if(temp[i][j]==0):
                result[i].append('Attack(Probably DoS)')
            if(temp[i][j]==2):
                result[i].append('Attack(Probably Probe)')
            if(temp[i][j]==3):
                result[i].append('Attack(Probably R2L)')
            if(temp[i][j]==4):
                result[i].append('Attack(Probably U2R)')	

for i in range(0,len(result)):
	print("Result of entry in ",i+1,"row:",result[i])
print()
print("Note:")
print("If the attack type is in format :Probably 'any_attack_type': then attack is confirmed and expected attacks are shown")
