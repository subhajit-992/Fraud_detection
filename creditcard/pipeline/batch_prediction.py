import os,sys
import pandas as pd
from datetime import datetime
import numpy as np
import shutil
from creditcard.exception import CreditCardsException
from creditcard.logger import logging
from creditcard.entity.config_entity import BatchPredictionConfig
from creditcard.ML.model_resolver import ModelResolver
from creditcard.utils import load_object
from glob import glob 


class CreditCardBatchPrediction:
    def __init__(self, data):
        try:
            self.data=data
        except Exception as e:
            raise CreditCardBatchPrediction(e,sys)

    def start_prediction(self):
        try:
            input_files = self.data

            if len(input_files)==0:
                logging.info(f"No file found hence closing the batch prediction")
                return None 

            model_resolver = ModelResolver()

            logging.info(f"Loading transformer to transform dataset")
            transformer = load_object(file_path=model_resolver.get_latest_transformer_path())

            logging.info(f"Loading model to make prediction")
            model = load_object(file_path=model_resolver.get_latest_model_path())

            logging.info(f"Target encoder to convert predicted column into categorical")
            target_encoder = load_object(file_path=model_resolver.get_latest_target_encoder_path())

            
            logging.info(f"copy input_file")
            df = input_files.copy()
            df.replace({"na":np.NAN},inplace=True)

            input_feature_names =  list(transformer.feature_names_in_)
            input_arr = transformer.transform(df[input_feature_names])

            prediction = model.predict(input_arr)
            prediction_probability = model.predict_proba(input_arr)
            #cat_prediction = target_encoder.inverse_transform(prediction)
            df["prediction"]=prediction
            submission = pd.DataFrame(prediction_probability,columns=["probability_of_not_default","probability _of_default"])
            df = pd.concat([df,submission],axis=1)
            #df["cat_pred"]=cat_prediction
            return df.prediction.values[0]

                #file_name = os.path.basename(file_path)
                #file_name = file_name.replace(".csv", f"_{datetime.now().strftime('%m%d%Y__%H%M%S')}.csv")
                #prediction_file_path = os.path.join(self.batch_config.outbox_dir,file_name)
                
                #logging.info(f"Saving prediction  file : {prediction_file_path}")
                #df.to_csv(prediction_file_path,index=False,header=True)

                #archive_file_path = os.path.join(self.batch_config.archive_dir,file_name)
                

                #shutil.copyfile(src=file_path, dst=archive_file_path)
                #logging.info(f"Copying input file into archive: {archive_file_path}")
                #logging.info(f"Removing file from inbox")
                #os.remove(file_path)
    
        except Exception as e:
            raise CreditCardsException(e, sys)