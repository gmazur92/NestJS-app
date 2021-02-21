import { IsIn, IsNotEmpty, IsOptional } from 'class-validator';
import { TasksStatus } from "../task-status.enum";

export class GetTasksFilterDto {
  @IsOptional()
  @IsIn([ TasksStatus.DONE, TasksStatus.IN_PROGRESS, TasksStatus.OPEN ])
  status: TasksStatus;

  @IsOptional()
  @IsNotEmpty()
  search: string;
}
